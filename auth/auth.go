/*
Package auth is responsible for user authentication.
*/
package auth

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/NordSecurity/nordvpn-linux/config"
	"github.com/NordSecurity/nordvpn-linux/core"
	daemonevents "github.com/NordSecurity/nordvpn-linux/daemon/events"
	"github.com/NordSecurity/nordvpn-linux/daemon/pb"
	"github.com/NordSecurity/nordvpn-linux/events"
	"github.com/NordSecurity/nordvpn-linux/internal"
	"github.com/google/uuid"
)

type DedicatedIPService struct {
	ExpiresAt string
	// ServerID will be set to NoServerSelected if server was not selected by the user
	ServerIDs []int64
}

// Checker provides information about current authentication.
type Checker interface {
	// IsLoggedIn returns true when the user is logged in.
	IsLoggedIn() bool
	// IsMFAEnabled returns true if Multifactor Authentication is enabled.
	IsMFAEnabled() (bool, error)
	// IsVPNExpired is used to check whether the user is allowed to use VPN
	IsVPNExpired() (bool, error)
	// GetDedicatedIPServices returns all available server IDs, if server is not selected by the user it will set
	// ServerID for that service to NoServerSelected
	GetDedicatedIPServices() ([]DedicatedIPService, error)
}

const (
	VPNServiceID         = 1
	DedicatedIPServiceID = 11
)

type expirationChecker interface {
	// isExpired checks if date in '2006-01-02 15:04:05' format has passed
	isExpired(date string) bool
}

type systemTimeExpirationChecker struct{}

// isTokenExpired reports whether the token is expired or not.
func (systemTimeExpirationChecker) isExpired(expiryTime string) bool {
	if expiryTime == "" {
		return true
	}

	expiry, err := time.Parse(internal.ServerDateFormat, expiryTime)
	if err != nil {
		return true
	}

	return time.Now().After(expiry)
}

// RenewingChecker does both authentication checks and renewals in case of expiration.
type RenewingChecker struct {
	cm                  config.Manager
	creds               core.CredentialsAPI
	expChecker          expirationChecker
	mfaPub              events.Publisher[bool]
	logoutPub           events.Publisher[events.DataAuthorization]
	errPub              events.Publisher[error]
	mu                  sync.Mutex
	accountUpdateEvents *daemonevents.AccountUpdateEvents
}

// NewRenewingChecker is a default constructor for RenewingChecker.
func NewRenewingChecker(cm config.Manager,
	creds core.CredentialsAPI,
	mfaPub events.Publisher[bool],
	logoutPub events.Publisher[events.DataAuthorization],
	errPub events.Publisher[error],
	accountUpdateEvents *daemonevents.AccountUpdateEvents,
) *RenewingChecker {
	return &RenewingChecker{
		cm:                  cm,
		creds:               creds,
		expChecker:          systemTimeExpirationChecker{},
		mfaPub:              mfaPub,
		logoutPub:           logoutPub,
		errPub:              errPub,
		accountUpdateEvents: accountUpdateEvents,
	}
}

// IsLoggedIn reports user login status.
//
// Thread safe.
func (r *RenewingChecker) IsLoggedIn() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	var cfg config.Config
	if err := r.cm.Load(&cfg); err != nil {
		return false
	}

	isLoggedIn := true
	for uid, data := range cfg.TokensData {
		if err := r.renew(uid, data); err != nil {
			isLoggedIn = false
		}
	}

	return cfg.AutoConnectData.ID != 0 && len(cfg.TokensData) > 0 && isLoggedIn
}

// IsMFAEnabled checks if user account has MFA turned on.
//
// Thread safe.
func (r *RenewingChecker) IsMFAEnabled() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.isMFAEnabled()
}

func (r *RenewingChecker) isMFAEnabled() (bool, error) {
	var cfg config.Config
	if err := r.cm.Load(&cfg); err != nil {
		extraErr := fmt.Errorf("checking MFA status, loading config: %w", err)
		r.errPub.Publish(extraErr)
		return false, extraErr
	}

	data := cfg.TokensData[cfg.AutoConnectData.ID]

	resp, err := r.creds.MultifactorAuthStatus(data.Token)
	if err != nil {
		extraErr := fmt.Errorf("querying MFA status: %w", err)
		r.errPub.Publish(extraErr)
		return false, extraErr
	}

	// inform subscribers
	r.mfaPub.Publish(resp.Status == internal.MFAEnabledStatusName)

	return resp.Status == internal.MFAEnabledStatusName, nil
}

// IsVPNExpired is used to check whether the user is allowed to use VPN
func (r *RenewingChecker) IsVPNExpired() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var cfg config.Config
	if err := r.cm.Load(&cfg); err != nil {
		return true, fmt.Errorf("loading config: %w", err)
	}

	data := cfg.TokensData[cfg.AutoConnectData.ID]
	if r.expChecker.isExpired(data.ServiceExpiry) {
		if err := r.fetchSaveServices(cfg.AutoConnectData.ID, &data); err != nil {
			return true, fmt.Errorf("updating service expiry token: %w", err)
		}
	}

	return r.expChecker.isExpired(data.ServiceExpiry), nil
}

func (r *RenewingChecker) GetDedicatedIPServices() ([]DedicatedIPService, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	services, err := r.fetchServices()
	if err != nil {
		return nil, fmt.Errorf("fetching available services: %w", err)
	}

	dipServices := []DedicatedIPService{}
	for _, service := range services {
		if service.Service.ID == DedicatedIPServiceID && !r.expChecker.isExpired(service.ExpiresAt) {
			serverIDs := []int64{}
			for _, server := range service.Details.Servers {
				serverIDs = append(serverIDs, server.ID)
			}
			dipServices = append(dipServices,
				DedicatedIPService{ExpiresAt: service.ExpiresAt, ServerIDs: serverIDs})
		}
	}

	return dipServices, nil
}

func (r *RenewingChecker) renew(uid int64, data config.TokenData) error {
	// We are renewing token if it is expired because we need to make some API calls later
	if r.expChecker.isExpired(data.TokenExpiry) {
		if data.IdempotencyKey == nil {
			key := uuid.New()
			data.IdempotencyKey = &key
			if err := r.cm.SaveWith(saveIdempotencyKey(uid, data)); err != nil {
				return fmt.Errorf("saving idempotency key: %w", err)
			}
		}
		if err := r.renewLoginToken(&data); err != nil {
			if errors.Is(err, core.ErrUnauthorized) ||
				errors.Is(err, core.ErrNotFound) ||
				errors.Is(err, core.ErrBadRequest) {
				return r.cm.SaveWith(Logout(uid, r.logoutPub))
			}
			return nil
		}
		// We renew NC credentials along the login token
		if err := r.renewNCCredentials(&data); err != nil {
			if errors.Is(err, core.ErrUnauthorized) ||
				errors.Is(err, core.ErrNotFound) ||
				errors.Is(err, core.ErrBadRequest) {
				return r.cm.SaveWith(Logout(uid, r.logoutPub))
			}
			return nil
		}
		if data.IsOAuth {
			if err := r.renewTrustedPassToken(&data); err != nil {
				if errors.Is(err, core.ErrUnauthorized) ||
					errors.Is(err, core.ErrNotFound) ||
					errors.Is(err, core.ErrBadRequest) {
					return r.cm.SaveWith(Logout(uid, r.logoutPub))
				}
			}
		}
		if err := r.cm.SaveWith(saveLoginToken(uid, data)); err != nil {
			return err
		}
	}

	// TrustedPass was introduced later on, so it's possible that valid data is not stored even though renew token
	// is still valid. In such cases we need to hit the api to get the initial value.
	isTrustedPassNotValid := (data.TrustedPassToken == "" || data.TrustedPassOwnerID == "")
	// TrustedPass is viable only in case of OAuth login.
	if data.IsOAuth && isTrustedPassNotValid {
		if err := r.renewTrustedPassToken(&data); err != nil {
			if errors.Is(err, core.ErrUnauthorized) ||
				errors.Is(err, core.ErrNotFound) ||
				errors.Is(err, core.ErrBadRequest) {
				return r.cm.SaveWith(Logout(uid, r.logoutPub))
			}
		}

		if err := r.cm.SaveWith(saveLoginToken(uid, data)); err != nil {
			return err
		}
	}

	if data.NordLynxPrivateKey == "" ||
		data.OpenVPNUsername == "" || data.OpenVPNPassword == "" {
		if err := r.renewVpnCredentials(&data); err != nil {
			return err
		}
		if err := r.cm.SaveWith(saveVpnServerCredentials(uid, data)); err != nil {
			return err
		}
	}

	return nil
}

func (r *RenewingChecker) renewLoginToken(data *config.TokenData) error {
	resp, err := r.creds.TokenRenew(data.RenewToken, *data.IdempotencyKey)
	if err != nil {
		return err
	}

	data.Token = resp.Token
	data.RenewToken = resp.RenewToken
	data.TokenExpiry = resp.ExpiresAt
	return nil
}

func (r *RenewingChecker) renewNCCredentials(data *config.TokenData) error {
	resp, err := r.creds.NotificationCredentials(data.Token, data.NCData.UserID.String())
	if err != nil {
		return err
	}

	data.NCData.Endpoint = resp.Endpoint
	data.NCData.Username = resp.Username
	data.NCData.Password = resp.Password
	return nil
}

func (r *RenewingChecker) renewTrustedPassToken(data *config.TokenData) error {
	resp, err := r.creds.TrustedPassToken(data.Token)
	if err != nil {
		return fmt.Errorf("getting trusted pass token data: %w", err)
	}

	data.TrustedPassOwnerID = resp.OwnerID
	data.TrustedPassToken = resp.Token

	return nil
}

func (r *RenewingChecker) renewVpnCredentials(data *config.TokenData) error {
	credentials, err := r.creds.ServiceCredentials(data.Token)
	if err != nil {
		return err
	}

	data.NordLynxPrivateKey = credentials.NordlynxPrivateKey
	data.OpenVPNUsername = credentials.Username
	data.OpenVPNPassword = credentials.Password
	return nil
}

// fetchSaveServices fetches services and updates data appropriately
func (r *RenewingChecker) fetchSaveServices(userId int64, data *config.TokenData) error {
	services, err := r.creds.Services(data.Token)
	if err != nil {
		return err
	}

	for _, service := range services {
		if service.Service.ID == VPNServiceID { // VPN service
			data.ServiceExpiry = service.ExpiresAt
		}
	}

	if err := r.cm.SaveWith(saveVpnExpirationDate(userId, *data)); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	r.accountUpdateEvents.SubscriptionUpdate.Publish(&pb.AccountModification{
		ExpiresAt: &data.ServiceExpiry,
	})

	return nil
}

func (r *RenewingChecker) fetchServices() ([]core.ServiceData, error) {
	var cfg config.Config
	if err := r.cm.Load(&cfg); err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	data := cfg.TokensData[cfg.AutoConnectData.ID]

	services, err := r.creds.Services(data.Token)
	if err != nil {
		return nil, fmt.Errorf("fetching available services: %w", err)
	}

	return services, nil
}

// saveLoginToken persists only token related data,
// it does not touch vpn specific data.
func saveLoginToken(userID int64, data config.TokenData) config.SaveFunc {
	return func(c config.Config) config.Config {
		user := c.TokensData[userID]
		defer func() { c.TokensData[userID] = user }()

		user.Token = data.Token
		user.RenewToken = data.RenewToken
		user.TokenExpiry = data.TokenExpiry
		user.NCData.Endpoint = data.NCData.Endpoint
		user.NCData.Username = data.NCData.Username
		user.NCData.Password = data.NCData.Password
		user.TrustedPassOwnerID = data.TrustedPassOwnerID
		user.TrustedPassToken = data.TrustedPassToken
		return c
	}
}

func saveVpnExpirationDate(userID int64, data config.TokenData) config.SaveFunc {
	return func(c config.Config) config.Config {
		user := c.TokensData[userID]
		defer func() { c.TokensData[userID] = user }()

		user.ServiceExpiry = data.ServiceExpiry
		return c
	}
}

func saveVpnServerCredentials(userID int64, data config.TokenData) config.SaveFunc {
	return func(c config.Config) config.Config {
		user := c.TokensData[userID]
		defer func() { c.TokensData[userID] = user }()

		user.NordLynxPrivateKey = data.NordLynxPrivateKey
		user.OpenVPNUsername = data.OpenVPNUsername
		user.OpenVPNPassword = data.OpenVPNPassword
		return c
	}
}

func saveIdempotencyKey(userID int64, data config.TokenData) config.SaveFunc {
	return func(c config.Config) config.Config {
		user := c.TokensData[userID]
		defer func() { c.TokensData[userID] = user }()

		user.IdempotencyKey = data.IdempotencyKey
		return c
	}
}

// Logout the user.
func Logout(user int64, logoutPub events.Publisher[events.DataAuthorization]) config.SaveFunc {
	return func(c config.Config) config.Config {
		if logoutPub != nil {
			// register stats instant logout with status success
			logoutPub.Publish(events.DataAuthorization{
				DurationMs: -1, EventTrigger: events.TriggerApp, EventStatus: events.StatusSuccess})
		}
		delete(c.TokensData, user)
		return c
	}
}
