package daemon

import (
	"fmt"
	"log"
	"os"

	"github.com/NordSecurity/nordvpn-linux/auth"
	"github.com/NordSecurity/nordvpn-linux/config"
	"github.com/NordSecurity/nordvpn-linux/core"
	"github.com/NordSecurity/nordvpn-linux/events"
	"github.com/NordSecurity/nordvpn-linux/internal"
)

type ConsentChecker interface {
	PrepareDaemonIfConsentNotCompleted()
	IsConsentFlowCompleted() bool
}

type consentMode uint

const (
	// consentModeStandard mode describes countries with less strict analytics consent requirements
	consentModeStandard consentMode = iota
	// consentModeGDPR mode describes countries with strict analytics consent requirements
	consentModeGDPR
)

func (c consentMode) String() string {
	switch c {
	case consentModeStandard:
		return "standard"
	case consentModeGDPR:
		return "GDPR"
	default:
		return fmt.Sprintf("consentMode(%d)", uint(c))
	}
}

type AnalyticsConsentChecker struct {
	isDevEnv    bool
	cm          config.Manager
	insightsAPI core.InsightsAPI
	authChecker auth.Checker
	analytics   events.Analytics
}

func NewConsentChecker(
	isDevEnv bool,
	cm config.Manager,
	insightsAPI core.InsightsAPI,
	authChecker auth.Checker,
	analytics events.Analytics,
) *AnalyticsConsentChecker {
	return &AnalyticsConsentChecker{
		isDevEnv,
		cm,
		insightsAPI,
		authChecker,
		analytics,
	}
}

// PrepareDaemonIfConsentNotCompleted sets up the daemon for analytics consent flow.
//
// If consent flow was completed, this is no-op. Otherwise:
//
// - using Insights API find user location
// - based on the location determine if user is in standard consent mode or GDPR mode (more strict)
//
// - for GDPR mode:
//   - do light logout, it forces the user to login to application which triggers consent flow
//
// - for standard mode:
//   - save consent as completed and accepted, no consent flow for standard mode countries
func (acc *AnalyticsConsentChecker) PrepareDaemonIfConsentNotCompleted() {
	if acc.IsConsentFlowCompleted() {
		// nothing to do
		return
	}

	consentMode := acc.consentModeFromUserLocation()

	// logout user if in GDPR consent mode so that any client trying to log in
	// will get the status informing it that user needs to complete analytics
	// consent flow
	if consentMode == consentModeGDPR && acc.authChecker.IsLoggedIn() {
		if err := acc.doLightLogout(); err != nil {
			log.Println(internal.WarningPrefix, "failed to perform light logout when user in gdpr mode:", err)
		}
		return
	}

	// standard mode has analytics enabled by default and no required
	// consent flow, so update the config with `AnalyticsConsent := true`
	if consentMode == consentModeStandard {
		if err := acc.setConsentGranted(); err != nil {
			log.Println(internal.WarningPrefix, "failed to set analytics consent to allowed when user in standard-mode:", err)
		}
	}
}

// IsConsentFlowCompleted reads configuration file and
// checks if `AnalyticsConsent` field is set.
func (acc *AnalyticsConsentChecker) IsConsentFlowCompleted() bool {
	var cfg config.Config
	if err := acc.cm.Load(&cfg); err != nil {
		log.Println(internal.ErrorPrefix, "failed to load config when checking consent flow", err)
		return false
	}
	switch cfg.AnalyticsConsent {
	case config.ConsentGranted, config.ConsentDenied:
		return true
	case config.ConsentUndefined:
		return false
	}
	return false
}

func (acc *AnalyticsConsentChecker) setConsentGranted() error {
	if err := acc.analytics.Enable(); err != nil {
		return err
	}
	return acc.cm.SaveWith(func(c config.Config) config.Config {
		c.AnalyticsConsent = config.ConsentGranted
		return c
	})
}

// consentModeFromUserLocation in a happy path, uses Insights API to get user's
// location and compares it to list of countries in standard mode, if not on the
// list, then user is in GDPR country.
//
// Additionally:
// - in case of issue with reading configuration, fallback to GDPR mode
// - if user has KillSwitch enabled, no traffic is going out, fallback to GDPR mode
// - if there is an issue with making API request, fallback to GDPR mode
func (acc *AnalyticsConsentChecker) consentModeFromUserLocation() consentMode {
	var cfg config.Config
	if err := acc.cm.Load(&cfg); err != nil {
		log.Println(internal.WarningPrefix, "failed to load config, falling back to GDPR mode:", err)
		// fallback to strict mode in case of an issue with config
		return consentModeGDPR
	}

	// can't determine user location with KS on, fallback to strict mode
	if cfg.KillSwitch {
		log.Println(internal.WarningPrefix, "KillSwitch active, falling back to GDPR mode")
		return consentModeGDPR
	}

	// fallback to strict mode in case of an issue with API
	insights, err := acc.insightsAPI.Insights()
	if err != nil {
		log.Println(internal.WarningPrefix, "insights api error, falling back to GDRP mode:", err)
		return consentModeGDPR
	}

	// fallback to strict mode in case of nil response
	if insights == nil {
		log.Println(internal.WarningPrefix, "insights data is nil, falling back to GDPR mode")
		return consentModeGDPR
	}

	cc := insights.CountryCode
	// allow override of country code in dev mode
	if acc.isDevEnv {
		if envVarCC, exists := os.LookupEnv("NORDVPN_USER_CC"); exists {
			log.Println(internal.DebugPrefix, "overriding user's country code to", envVarCC)
			cc = envVarCC
		}
	}

	mode := modeForCountryCode(core.NewCountryCode(cc))
	log.Printf(internal.DebugPrefix+" consent mode for country code '%s': %s\n", cc, mode)
	return mode
}

// doLightLogout performs minimal logout operation which will result in
// `auth.Checker.IsLoggedIn` returning false and meshnet being disabled.
//
// The logout operation is needed to direct user to go through `login` command
// which will trigger consent flow, but at the same time we don't want to
// make full, invasive logout with token invalidation etc., so we are doing
// minimal work which will require user to trigger login.
// Meshnet also has to be disabled because the startup happens on daemon start
// and it's not retried later, so logged out account won't have meshnet working
// even if it was enabled in the configuration during startup.
func (acc *AnalyticsConsentChecker) doLightLogout() error {
	return acc.cm.SaveWith(func(c config.Config) config.Config {
		delete(c.TokensData, c.AutoConnectData.ID)
		c.AutoConnectData.ID = 0
		c.Mesh = false
		c.MeshPrivateKey = ""
		return c
	})
}

// modeForCountryCode returns analytics consent mode.
//
// It uses country code and list of lowercase county codes in standard mode to
// check it. Countries not on the standard mode list fall into GDPR mode.
func modeForCountryCode(cc core.CountryCode) consentMode {
	switch cc.String() {
	case "us", "ca", "jp", "au":
		return consentModeStandard
	default:
		return consentModeGDPR
	}
}
