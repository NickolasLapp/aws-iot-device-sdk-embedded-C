/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <string.h>
#include <timer_platform.h>
#include <network_interface.h>

#include "aws_iot_error.h"
#include "aws_iot_log.h"
#include "network_interface.h"
#include "network_platform.h"

/* socket includes */
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>


/* This is the value used for ssl read timeout */
#define IOT_SSL_READ_TIMEOUT 10

void _wolfSSL_log(int level, const char *msg)
{
    printf("WOLFSSL_LOG_%d:\t\t%s\n", level, msg);
}

void _iot_tls_set_connect_params(Network *pNetwork, char *pRootCALocation, char *pDeviceCertLocation,
                                 char *pDevicePrivateKeyLocation, char *pDestinationURL,
                                 uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag) {
    FUNC_ENTRY
    pNetwork->tlsConnectParams.DestinationPort = destinationPort;
    pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
    pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
    pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
    pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
    pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
    pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;
    FUNC_EXIT
}

IoT_Error_t iot_tls_init(Network *pNetwork, char *pRootCALocation, char *pDeviceCertLocation,
                         char *pDevicePrivateKeyLocation, char *pDestinationURL,
                         uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag) {
    FUNC_ENTRY
    pNetwork->connect = iot_tls_connect;
    pNetwork->read = iot_tls_read;
    pNetwork->write = iot_tls_write;
    pNetwork->disconnect = iot_tls_disconnect;
    pNetwork->isConnected = iot_tls_is_connected;
    pNetwork->destroy = iot_tls_destroy;

    _iot_tls_set_connect_params(pNetwork, pRootCALocation, pDeviceCertLocation, pDevicePrivateKeyLocation,
                                pDestinationURL, destinationPort, timeout_ms, ServerVerificationFlag);

    wolfSSL_Init();
#ifdef IOT_DEBUG
    wolfSSL_Debugging_ON();
    wolfSSL_SetLoggingCb((wolfSSL_Logging_cb)&_wolfSSL_log);
#endif
    FUNC_EXIT_RC(SUCCESS)
    return SUCCESS;
}

IoT_Error_t _iot_tls_ctx_init(Network *pNetwork) {
    FUNC_ENTRY
    int ret = 0;
    WOLFSSL_CTX* ctx;
    pNetwork->tlsDataParams.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    ctx = pNetwork->tlsDataParams.ctx;

    if(!pNetwork->tlsDataParams.ctx) {
        IOT_ERROR("Unable to create WOLFSSL_CTX Object");
        FUNC_EXIT_RC(NETWORK_SSL_UNKNOWN_ERROR)
        return NETWORK_SSL_UNKNOWN_ERROR;
    }

    IOT_DEBUG("Loading the CA root certificate ...");
    ret = wolfSSL_CTX_load_verify_locations(ctx, pNetwork->tlsConnectParams.pRootCALocation, NULL);
    if(ret != SSL_SUCCESS) {
        IOT_ERROR("Unable to load root ca. wolfSSL returned: %d", ret);
        FUNC_EXIT_RC(NETWORK_X509_ROOT_CRT_PARSE_ERROR)
        return NETWORK_X509_ROOT_CRT_PARSE_ERROR;
    }
    IOT_DEBUG("Root CA Loaded Successfully");

    IOT_DEBUG("Loading the client certificate");
    ret = wolfSSL_CTX_use_certificate_chain_file(ctx, pNetwork->tlsConnectParams.pDeviceCertLocation);
    if(ret != SSL_SUCCESS) {
        IOT_ERROR("Unable to load client cert. wolfSSL returned: %d", ret);
        FUNC_EXIT_RC(NETWORK_X509_DEVICE_CRT_PARSE_ERROR)
        return NETWORK_X509_DEVICE_CRT_PARSE_ERROR;
    }
    IOT_DEBUG("Client Cert Loaded Successfully");

    IOT_DEBUG("Loading Client Private Key");
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, pNetwork->tlsConnectParams.pDevicePrivateKeyLocation,
                    SSL_FILETYPE_PEM);
    if(ret != SSL_SUCCESS) {
        IOT_ERROR("Unable to load client private key. wolfSSL returned: %d", ret);
        FUNC_EXIT_RC(NETWORK_PK_PRIVATE_KEY_PARSE_ERROR)
        return NETWORK_PK_PRIVATE_KEY_PARSE_ERROR;
    }
    IOT_DEBUG("Client Private Key Loaded Successfully");
    FUNC_EXIT_RC(SUCCESS)
    return SUCCESS;
}




IoT_Error_t iot_tls_is_connected(Network *pNetwork) {
    FUNC_ENTRY
    /* Use this to add implementation which can check for physical layer disconnect */
    FUNC_EXIT_RC(NETWORK_PHYSICAL_LAYER_CONNECTED)
    return NETWORK_PHYSICAL_LAYER_CONNECTED;
}

IoT_Error_t iot_tls_connect(Network *pNetwork, TLSConnectParams *params) {
    int ret = 0, debug_err;
    const char *pers = "aws_iot_tls_wrapper";
    TLSDataParams *tlsDataParams = NULL;

    int port;
    int opts;
    char* host;
    struct hostent *server;
    struct sockaddr_in serv_addr;
    struct timeval timeout;
    int sockfd;

    FUNC_ENTRY


    if(NULL == pNetwork) {
        FUNC_EXIT_RC(NULL_VALUE_ERROR)
        return NULL_VALUE_ERROR;
    }

    if(NULL != params) {
        _iot_tls_set_connect_params(pNetwork, params->pRootCALocation, params->pDeviceCertLocation,
                                    params->pDevicePrivateKeyLocation, params->pDestinationURL,
                                    params->DestinationPort, params->timeout_ms, params->ServerVerificationFlag);
    }

    tlsDataParams = &(pNetwork->tlsDataParams);

    if(!tlsDataParams->ctx) {
        ret = _iot_tls_ctx_init(pNetwork);
        if(ret!=SUCCESS) {
            FUNC_EXIT_RC((IoT_Error_t)ret);
            return (IoT_Error_t)ret;
        }
    }

    IOT_DEBUG("Connecting to %s/%d...",
                            pNetwork->tlsConnectParams.pDestinationURL,
                            pNetwork->tlsConnectParams.DestinationPort);
    host = pNetwork->tlsConnectParams.pDestinationURL;
    port = pNetwork->tlsConnectParams.DestinationPort;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        IOT_ERROR("ERROR: failed to create the socket\n");
        FUNC_EXIT_RC(TCP_CONNECTION_ERROR)
        return TCP_CONNECTION_ERROR;
    }

    /* Set the socket options to use blocking I/O */
    opts = fcntl(sockfd, F_GETFL);
    if (fcntl(sockfd, F_SETFL, opts & ~O_NONBLOCK) == -1) {
        IOT_ERROR("fcntl failed to set blocking\n");
        FUNC_EXIT_RC(TCP_CONNECTION_ERROR)
        return TCP_CONNECTION_ERROR;
    }

    memset(&timeout, 0, sizeof(timeout));
    timeout.tv_sec = pNetwork->tlsConnectParams.timeout_ms / 1000;
    timeout.tv_usec = (pNetwork->tlsConnectParams.timeout_ms % 1000) *  1000;

    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        IOT_ERROR("setsockopt for recv timeout failed.\n");
        FUNC_EXIT_RC(TCP_CONNECTION_ERROR)
        return TCP_CONNECTION_ERROR;
    }

    if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        IOT_ERROR("setsockopt for send timeout failed.\n");
        FUNC_EXIT_RC(TCP_CONNECTION_ERROR)
        return TCP_CONNECTION_ERROR;
    }

    server = gethostbyname(host);
    if(server == NULL) {
        IOT_ERROR("Failed to get host by name");
        FUNC_EXIT_RC(TCP_CONNECTION_ERROR)
        return TCP_CONNECTION_ERROR;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    ret = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));


    if(ret < 0) {
        IOT_ERROR("TCP Connection failed!");
        IOT_ERROR("Connect ret=%d", ret);
        IOT_ERROR("Errno=%d", errno);
        FUNC_EXIT_RC(TCP_CONNECTION_ERROR)
        return TCP_CONNECTION_ERROR;
    }

    tlsDataParams->ssl = wolfSSL_new(tlsDataParams->ctx);
    if(!tlsDataParams->ssl) {
        IOT_ERROR("Unable to create WOLFSSL Object");
        FUNC_EXIT_RC(NETWORK_SSL_UNKNOWN_ERROR)
        return NETWORK_SSL_UNKNOWN_ERROR;
    }

    wolfSSL_set_fd(tlsDataParams->ssl, sockfd);
    wolfSSL_set_using_nonblock(tlsDataParams->ssl, 0);

    while((ret = wolfSSL_connect(tlsDataParams->ssl)) < 0
          && (debug_err = (wolfSSL_get_error(tlsDataParams->ssl, ret) == SSL_ERROR_WANT_READ) ||
              wolfSSL_get_error(tlsDataParams->ssl, ret) == SSL_ERROR_WANT_WRITE));

    if(ret != SSL_SUCCESS) {
        IOT_ERROR("wolfSSL_Connect Failed");
        FUNC_EXIT_RC(SSL_CONNECTION_ERROR)
        return SSL_CONNECTION_ERROR;
    } else {
        ret = SUCCESS;
    }

    IOT_DEBUG("SSL Connect successful!");

    /* set socket opts to read/write timeouts */
    timeout.tv_sec = IOT_SSL_READ_TIMEOUT / 1000;
    timeout.tv_usec = (IOT_SSL_READ_TIMEOUT % 1000) *  1000;
    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        IOT_ERROR("setsockopt for recv timeout failed.\n");
        FUNC_EXIT_RC(TCP_CONNECTION_ERROR)
        return TCP_CONNECTION_ERROR;
    }

    if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        IOT_ERROR("setsockopt for send timeout failed.\n");
        FUNC_EXIT_RC(TCP_CONNECTION_ERROR)
        return TCP_CONNECTION_ERROR;
    }

    FUNC_EXIT_RC((IoT_Error_t) ret)
    return (IoT_Error_t) ret;
}

IoT_Error_t iot_tls_write(Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer, size_t *written_len) {
    size_t written_so_far;
    bool isErrorFlag = false;
    int frags, ret;
    TLSDataParams * tlsDataParams = &(pNetwork->tlsDataParams);
    WOLFSSL* ssl = tlsDataParams->ssl;
    FUNC_ENTRY

    for(written_so_far = 0, frags = 0;
            written_so_far < len && !has_timer_expired(timer); written_so_far += ret, frags++) {
        while(!has_timer_expired(timer) &&
               (ret = wolfSSL_write(ssl, pMsg + written_so_far, len - written_so_far)) <= 0) {
            if(wolfSSL_get_error(ssl, ret) != SSL_ERROR_WANT_WRITE) {
                IOT_ERROR(" failed. wolfSSL_write returning %d", ret);
                isErrorFlag = true;
                break;
            }
        }
        if(isErrorFlag) {
            break;
        }
    }

    *written_len = written_so_far;
    if(isErrorFlag) {
        FUNC_EXIT_RC(NETWORK_SSL_WRITE_ERROR)
        return NETWORK_SSL_WRITE_ERROR;
    } else if(has_timer_expired(timer) && written_so_far != len) {
        FUNC_EXIT_RC(NETWORK_SSL_WRITE_TIMEOUT_ERROR)
        return NETWORK_SSL_WRITE_TIMEOUT_ERROR;
    }

    FUNC_EXIT_RC(SUCCESS)
    return SUCCESS;
}

IoT_Error_t iot_tls_read(Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer, size_t *read_len) {
    WOLFSSL *ssl = pNetwork->tlsDataParams.ssl;
    size_t rxLen = 0;
    int ret;
    FUNC_ENTRY

    while (len > 0) {
        /* This read will timeout after IOT_SSL_READ_TIMEOUT if there's no data to be read */
        ret = wolfSSL_read(ssl, pMsg, len);
        if (ret > 0) {
            rxLen += ret;
            pMsg += ret;
            len -= ret;
        } else if (ret == 0 || (ret < 0 && wolfSSL_get_error(ssl, ret) != SSL_ERROR_WANT_READ)) {
            FUNC_EXIT_RC(NETWORK_SSL_READ_ERROR)
            return NETWORK_SSL_READ_ERROR;
        }

        /* Evaluate timeout after the read to make sure read is done at least once */
        if (has_timer_expired(timer)) {
            break;
        }
    }

    if (len == 0) {
        *read_len = rxLen;
        FUNC_EXIT_RC(SUCCESS)
        return SUCCESS;
    }

    if (rxLen == 0) {
        FUNC_EXIT_RC(NETWORK_SSL_NOTHING_TO_READ)
        return NETWORK_SSL_NOTHING_TO_READ;
    } else {
        FUNC_EXIT_RC(NETWORK_SSL_READ_TIMEOUT_ERROR)
        return NETWORK_SSL_READ_TIMEOUT_ERROR;
    }

}

IoT_Error_t iot_tls_disconnect(Network *pNetwork) {
    FUNC_ENTRY
    WOLFSSL *ssl = pNetwork->tlsDataParams.ssl;
    wolfSSL_shutdown(ssl);

    wolfSSL_free(ssl);
    pNetwork->tlsDataParams.ssl = NULL;

    FUNC_EXIT_RC(SUCCESS)
    return SUCCESS;
}

IoT_Error_t iot_tls_destroy(Network *pNetwork) {
    FUNC_ENTRY
    wolfSSL_CTX_free(pNetwork->tlsDataParams.ctx);
    pNetwork->tlsDataParams.ctx = NULL;
    wolfSSL_Cleanup();
    return SUCCESS;
}

#ifdef __cplusplus
}
#endif
