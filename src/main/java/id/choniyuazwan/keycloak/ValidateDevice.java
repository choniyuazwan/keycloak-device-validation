package id.choniyuazwan.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.jboss.logging.Logger;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.*;

public class ValidateDevice extends AbstractDirectGrantAuthenticator {

  public static final String PROVIDER_ID = "direct-grant-validate-device";
  private static final Logger log = Logger.getLogger(ValidateDevice.class);

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String deviceParam = retrieveDevice(context);
    if (deviceParam == null) {
      Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Missing parameter: device");
      context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    } else if(deviceParam.trim().isEmpty()) {
      Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_value", "Device value can't empty");
      context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    UserModel user = context.getUser();
    String deviceUser = user.getAttribute("device").get(0);
    log.info("deviceUser " + deviceUser);
    log.info("deviceParam " + deviceParam);

    try {
      if(deviceUser == null || deviceUser.trim().isEmpty()) {
        user.setAttribute("device", Collections.singletonList(deviceParam));
      } else if (!deviceUser.equals(deviceParam)) {
        Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_value", "Invalid device value");
        context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
        return;
      }
    } catch (ModelDuplicateException mde) {
      ServicesLogger.LOGGER.modelDuplicateException(mde);
      Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Invalid device credentials");
      context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    context.setUser(user);
    context.success();
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }


  @Override
  public String getDisplayType() {
    return "Device Validation";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED
  };

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public String getHelpText() {
    return "Validates the device supplied as a 'device' form parameter in direct grant request";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return new LinkedList<>();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  protected String retrieveDevice(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
    return inputData.getFirst("device");
  }
}
