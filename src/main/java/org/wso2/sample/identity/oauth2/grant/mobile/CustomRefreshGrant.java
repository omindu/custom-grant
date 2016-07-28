package org.wso2.sample.identity.oauth2.grant.mobile;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;

import java.util.UUID;

public class CustomRefreshGrant extends RefreshGrantHandler {

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        RequestParameter[] requestParameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        for (RequestParameter parameter : requestParameters) {
            if ("refresh_token".equals(parameter.getKey())) {
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().setRefreshToken(parameter.getValue()[0]);
            }
        }

        if (super.validateGrant(tokReqMsgCtx)) {
            tokReqMsgCtx.addProperty("custom_access_token", "crat-" + UUID
                    .randomUUID().toString());
            tokReqMsgCtx.addProperty("custom_refresh_token", "crrt-" + UUID
                    .randomUUID().toString());
            return true;
        }

        return false;
    }
}
