/*
 * NF Context for NSSF
 *
 * Configuration of NSSF itself shall be accessed with NSSF context
 * Configuration of network slices shall be accessed with configuration factory
 */

package context

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/free5gc/nssf/internal/logger"
	"github.com/free5gc/nssf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
)

const NRF_PORT = 29510

var nssfContext = NSSFContext{}

// Initialize NSSF context with default value
func Init() {
	nssfContext.NfId = uuid.New().String()

	nssfContext.Name = "NSSF"

	nssfContext.UriScheme = models.UriScheme_HTTPS
	nssfContext.RegisterIPv4 = factory.NssfSbiDefaultIPv4
	nssfContext.SBIPort = factory.NssfSbiDefaultPort

	serviceName := []models.ServiceName{
		models.ServiceName_NNSSF_NSSELECTION,
		models.ServiceName_NNSSF_NSSAIAVAILABILITY,
	}
	nssfContext.NfService = initNfService(serviceName, "1.0.0")

	nssfContext.NrfUri = fmt.Sprintf("%s://%s:%d", models.UriScheme_HTTPS, nssfContext.RegisterIPv4, NRF_PORT)
}

type NFContext interface {
	AuthorizationCheck(token string, serviceName models.ServiceName) error
}

var _ NFContext = &NSSFContext{}

type NSSFContext struct {
	NfId         string
	Name         string
	UriScheme    models.UriScheme
	RegisterIPv4 string
	// HttpIpv6Address string
	BindingIPv4       string
	SBIPort           int
	NfService         map[models.ServiceName]models.NrfNfManagementNfService
	NrfUri            string
	NrfCertPem        string
	NrfNfInstanceID   string
	SupportedPlmnList []models.PlmnId
	OAuth2Required    bool
}

// Initialize NSSF context with configuration factory
func InitNssfContext() {
	nssfConfig := factory.NssfConfig
	if nssfConfig.Configuration.NssfName != "" {
		nssfContext.Name = nssfConfig.Configuration.NssfName
	}

	nssfContext.NfId = nssfConfig.GetNfInstanceId()
	nssfContext.Name = "NSSF"
	nssfContext.UriScheme = nssfConfig.Configuration.Sbi.Scheme
	nssfContext.RegisterIPv4 = nssfConfig.Configuration.Sbi.RegisterIPv4
	nssfContext.SBIPort = nssfConfig.Configuration.Sbi.Port
	nssfContext.BindingIPv4 = os.Getenv(nssfConfig.Configuration.Sbi.BindingIPv4)
	if nssfContext.BindingIPv4 != "" {
		logger.CtxLog.Info("Parsing ServerIPv4 address from ENV Variable.")
	} else {
		nssfContext.BindingIPv4 = nssfConfig.Configuration.Sbi.BindingIPv4
		if nssfContext.BindingIPv4 == "" {
			logger.CtxLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
			nssfContext.BindingIPv4 = "0.0.0.0"
		}
	}

	nssfContext.NfService = initNfService(nssfConfig.Configuration.ServiceNameList, nssfConfig.Info.Version)

	if nssfConfig.Configuration.NrfUri != "" {
		nssfContext.NrfUri = nssfConfig.Configuration.NrfUri
	} else {
		logger.InitLog.Warn("NRF Uri is empty! Using localhost as NRF IPv4 address.")
		nssfContext.NrfUri = fmt.Sprintf("%s://%s:%d", nssfContext.UriScheme, "127.0.0.1", NRF_PORT)
	}
	nssfContext.NrfCertPem = nssfConfig.Configuration.NrfCertPem
	nssfContext.NrfNfInstanceID = nssfConfig.Configuration.NrfNfInstanceId
	nssfContext.SupportedPlmnList = nssfConfig.Configuration.SupportedPlmnList
}

func initNfService(serviceName []models.ServiceName, version string) (
	nfService map[models.ServiceName]models.NrfNfManagementNfService,
) {
	versionUri := "v" + strings.Split(version, ".")[0]
	nfService = make(map[models.ServiceName]models.NrfNfManagementNfService)
	for idx, name := range serviceName {
		nfService[name] = models.NrfNfManagementNfService{
			ServiceInstanceId: strconv.Itoa(idx),
			ServiceName:       name,
			Versions: []models.NfServiceVersion{
				{
					ApiFullVersion:  version,
					ApiVersionInUri: versionUri,
				},
			},
			Scheme:          nssfContext.UriScheme,
			NfServiceStatus: models.NfServiceStatus_REGISTERED,
			ApiPrefix:       GetIpv4Uri(),
			IpEndPoints: []models.IpEndPoint{
				{
					Ipv4Address: nssfContext.RegisterIPv4,
					Transport:   models.NrfNfManagementTransportProtocol_TCP,
					Port:        int32(nssfContext.SBIPort),
				},
			},
		}
	}

	return
}

func GetIpv4Uri() string {
	return fmt.Sprintf("%s://%s:%d", nssfContext.UriScheme, nssfContext.RegisterIPv4, nssfContext.SBIPort)
}

func GetSelf() *NSSFContext {
	return &nssfContext
}

func (c *NSSFContext) GetTokenCtx(serviceName models.ServiceName, targetNF models.NrfNfManagementNfType) (
	context.Context, *models.ProblemDetails, error,
) {
	if !c.OAuth2Required {
		return context.TODO(), nil, nil
	}
	return oauth.GetTokenCtx(c.tokenRequest(serviceName, targetNF))
}

func (c *NSSFContext) GetTokenCtxForNFInstance(serviceName models.ServiceName,
	targetNF models.NrfNfManagementNfType, targetNFInstanceID string,
) (context.Context, *models.ProblemDetails, error) {
	if !c.OAuth2Required {
		return context.TODO(), nil, nil
	}
	targetID, err := uuid.Parse(strings.TrimSpace(targetNFInstanceID))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target NF instance ID: %w", err)
	}
	if targetID.Version() != 4 {
		return nil, nil, fmt.Errorf("invalid target NF instance ID: UUID must be version 4")
	}
	return oauth.GetTokenCtx(c.tokenRequestForNFInstance(serviceName, targetNF, targetNFInstanceID))
}

func (c *NSSFContext) GetTokenCtxForNRF(serviceName models.ServiceName) (
	context.Context, *models.ProblemDetails, error,
) {
	return c.GetTokenCtxForNFInstance(serviceName, models.NrfNfManagementNfType_NRF, c.NrfNfInstanceID)
}

func (c *NSSFContext) tokenRequest(serviceName models.ServiceName,
	targetNF models.NrfNfManagementNfType,
) oauth.TokenRequest {
	return oauth.TokenRequest{
		ConsumerNFType: models.NrfNfManagementNfType_NSSF, ConsumerNFInstanceID: c.NfId,
		TargetNFType: targetNF, NRFURI: c.NrfUri, Scope: string(serviceName),
	}
}

func (c *NSSFContext) tokenRequestForNFInstance(serviceName models.ServiceName,
	targetNF models.NrfNfManagementNfType, targetNFInstanceID string,
) oauth.TokenRequest {
	request := c.tokenRequest(serviceName, targetNF)
	request.TargetNFInstanceID = targetNFInstanceID
	return request
}

func (c *NSSFContext) SetOAuth2Required(required bool) error {
	if !required {
		c.OAuth2Required = false
		return nil
	}
	if strings.TrimSpace(c.NrfCertPem) == "" {
		return fmt.Errorf("OAuth2 enabled but NRF certificate path is empty")
	}
	if strings.TrimSpace(c.NrfUri) == "" {
		return fmt.Errorf("OAuth2 enabled but NRF URI is empty")
	}
	if err := uuid.Validate(c.NrfNfInstanceID); err != nil {
		return fmt.Errorf("OAuth2 enabled but trusted NRF instance ID is invalid: %w", err)
	}
	c.OAuth2Required = true
	return nil
}

func (c *NSSFContext) AuthorizationCheck(token string, serviceName models.ServiceName) error {
	if !c.OAuth2Required {
		logger.UtilLog.Debugf("NSSFContext::AuthorizationCheck: OAuth2 not required\n")
		return nil
	}

	logger.UtilLog.Debugf("NSSFContext::AuthorizationCheck: token[%s] serviceName[%s]\n", token, serviceName)
	return oauth.VerifyOAuth(token, string(serviceName), oauth.AudiencePolicy{
		NFInstanceID: c.NfId, NFType: models.NrfNfManagementNfType_NSSF,
	}, c.NrfNfInstanceID, c.NrfCertPem)
}
