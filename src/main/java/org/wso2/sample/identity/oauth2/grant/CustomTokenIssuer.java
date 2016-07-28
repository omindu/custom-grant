package org.wso2.sample.identity.oauth2.grant;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;

public class CustomTokenIssuer extends OauthTokenIssuerImpl {

    @Override
    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {

        if ("mobile".equals(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType()) || "extended_refresh".equals
                (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType())) {
            return (String) tokReqMsgCtx.getProperty("custom_access_token");
        }
        return super.accessToken(tokReqMsgCtx);
    }

    @Override
    public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {

        if ("mobile".equals(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType()) || "extended_refresh".equals
                (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType())) {
            return (String) tokReqMsgCtx.getProperty("custom_refresh_token");
        }
        return super.refreshToken(tokReqMsgCtx);
    }
}
