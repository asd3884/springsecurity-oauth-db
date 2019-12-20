package com.aak.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
    Logger logger=LoggerFactory.getLogger(AuthorizationServerConfiguration.class);


    @Bean
    @ConfigurationProperties(prefix = "spring.datasource")
    public DataSource oauthDataSource() {
        return DataSourceBuilder.create().build();
    }

    @Bean
    public JdbcClientDetailsService clientDetailsService() {
        return new JdbcClientDetailsService(oauthDataSource());
    }

    @Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(oauthDataSource());
    }

    @Bean
    public ApprovalStore approvalStore() {
        return new JdbcApprovalStore(oauthDataSource());
    }

    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new JdbcAuthorizationCodeServices(oauthDataSource());
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        logger.info("授权开始---------------------");
        clients.withClientDetails(clientDetailsService());
//        List<OauthClientDetails> clientsList=oauthClientDetailsRepository.findAll();
//        for(OauthClientDetails oauth: clientsList){
//            clients.inMemory()
//                    .withClient(oauth.getClient_id())//客户端id
//                    .scopes(oauth.getScope())//作用域
//                    .authorizedGrantTypes(oauth.getAuthorized_grant_types())//授权码模式
//                    .redirectUris(oauth.getWeb_server_redirect_uri()) //跳转
//                    .secret(oauth.getClient_secret())//密匙
//                    .accessTokenValiditySeconds(10000) //token过期时间
//                    .refreshTokenValiditySeconds(100000); //refresh过期时间*/
//        }

        logger.info("===============配置授权服务器完成=========");
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.allowFormAuthenticationForClients();
        oauthServer.checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .approvalStore(approvalStore())
                .authorizationCodeServices(authorizationCodeServices())
                .tokenStore(tokenStore());
    }
}
