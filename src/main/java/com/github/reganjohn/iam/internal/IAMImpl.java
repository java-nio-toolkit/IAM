/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.internal;

import com.github.adamorgan.jnt.api.JNT;
import com.github.adamorgan.jnt.api.JNTBuilder;
import com.github.adamorgan.jnt.api.managers.CacheObjectManager;
import com.github.adamorgan.jnt.api.managers.ContentEncodingManager;
import com.github.adamorgan.jnt.api.managers.ContentObjectManager;
import com.github.adamorgan.jnt.api.managers.DigestObjectManager;
import com.github.adamorgan.jnt.api.managers.OriginAccessManager;
import com.github.adamorgan.jnt.api.managers.ProofObjectManager;
import com.github.adamorgan.jnt.api.managers.RestRateLimiter;
import com.github.adamorgan.jnt.api.managers.SignatureObjectManager;
import com.github.adamorgan.jnt.api.requests.Method;
import com.github.adamorgan.jnt.api.socket.DefaultSocketManagerBuilder;
import com.github.adamorgan.jnt.api.socket.SocketManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicRequestSendHandlerImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicResponseReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.managers.*;
import com.github.adamorgan.jnt.internal.requests.restaction.AccessEntryActionImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.config.OriginAccessConfig;
import com.github.adamorgan.jnt.internal.utils.tracker.SocketTracker;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.managers.AccessSignatureManager;
import com.github.reganjohn.iam.api.managers.GlobalAccessManager;
import com.github.reganjohn.iam.internal.managers.*;
import com.github.reganjohn.iam.internal.requests.restactions.UserRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.applications.*;
import com.github.reganjohn.iam.internal.requests.restactions.interactions.ApplicationInteractionCreateActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.interactions.ApplicationInteractionDeleteActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.interactions.ApplicationInteractionOverrideActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.interactions.ApplicationInteractionRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.interactions.ApplicationInteractionCallbackActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.entitlements.*;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserCreateActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserDeleteActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserEditActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.sessions.*;
import com.github.reganjohn.iam.internal.requests.restactions.webhooks.*;
import com.reganjohn.c4j.api.JCA;
import com.reganjohn.c4j.api.JCABuilder;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.Consistency;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.Compression;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.jdt.api.JDT;
import com.reganjohn.jdt.api.JDTBuilder;
import io.micrometer.core.instrument.Metrics;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.util.ResourceLeakDetector;
import io.netty.util.internal.EmptyArrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.security.Security;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class IAMImpl implements IAM
{
    static
    {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.SIMPLE);
    }

    private final JNT api;
    private final JCA jca;
    private final GlobalAccessManager manager;
    private final SocketManager socketManager;
    private final EventLoopGroup socketPool = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
    private final JDT addressController;
    private final String baseUri;
    private final AccessSignatureManagerImpl accessSignatureManager = new AccessSignatureManagerImpl();
    private final SocketTracker tracker = new SocketTracker(Metrics.globalRegistry, "unknown");

    private final EntityBuilder entityBuilder = new EntityBuilder(this);

    public static void main(String[] args) throws Exception
    {
        IAMImpl api = new IAMImpl(8080, "https://localhost.com");
        Runtime.getRuntime().addShutdownHook(new Thread(api::shutdown));
    }

    @Nonnull
    private OriginAccessConfig cors()
    {
        return new OriginAccessManager.Builder(String.join(", ", manager.getAudiences()))
                .allowMethods(Method.GET, Method.POST, Method.PUT, Method.PATCH, Method.DELETE)
                .allowHeaders(ProofObjectManager.AUTHORIZATION, ProofObjectManager.DPOP, ContentObjectManager.CONTENT_TYPE,
                        ContentEncodingManager.CONTENT_ENCODING, DigestObjectManager.CONTENT_DIGEST, DigestObjectManager.WANT_CONTENT_DIGEST,
                        SignatureObjectManager.SIGN, SignatureObjectManager.SIGN_IN, CacheObjectManager.MATCH, CacheObjectManager.NONE_MATCH,
                        CacheObjectManager.MODIFIED_SINCE, CacheObjectManager.UNMODIFIED_SINCE)
                .allowExposeHeaders(ProofObjectManager.CHALLENGE, ProofObjectManager.WWW_AUTHENTICATE, RestRateLimiter.RETRY_AFTER_HEADER,
                        RestRateLimiter.LIMIT_HEADER, RestRateLimiter.REMAINING_HEADER, RestRateLimiter.RESET_HEADER, RestRateLimiter.POLICY_HEADER,
                        CacheObjectManager.ETAG, DigestObjectManager.CONTENT_DIGEST, SignatureObjectManager.SIGN, SignatureObjectManager.SIGN_IN)
                .allowCredentials(false)
                .allowMaxAge(3600)
                .build();
    }

    @Nonnull
    private static byte[] getNonceSecret()
    {
        String secret = System.getenv("nonce.secret");
        if (Helpers.isEmpty(secret))
            return EmptyArrays.EMPTY_BYTES;
        byte[] decoded = Base64.getDecoder().decode(secret.trim());
        Checks.inRange(decoded.length, 32, 64, "nonce.secret");
        return decoded;
    }

    @Nonnull
    private JCA buildInstance()
    {
        return JCABuilder.create("localhost", 9042)
                .setApplicationName("Test Client")
                .setProtocolVersion(5)
                .setCompression(Compression.LZ4)
                .setDefaultConsistency(Consistency.QUORUM)
                .setSecret("cassandra", "cassandra")
                .setAutoReconnect(true)
                .build();
    }

    @Nonnull
    private SocketManager createWebhookManager()
    {
        return DefaultSocketManagerBuilder.create()
                .setIdentifierString("IAM")
                .addEventListenerProvider(ClassicRequestSendHandlerImpl::new)
                .addEventListenerProvider(ClassicResponseReceiveHandlerImpl::new)
                .addEventListenerProvider(() -> new ClassicIdleObjectManagerImpl(30, 30, 5))
                .addEventListenerProvider(ProofSignatureManagerImpl::new)
                .addEventListeners(manager)
                .addEventListenerProvider(ContentObjectManagerImpl::new)
                .addEventListenerProvider(DigestObjectManagerImpl::new)
                .setConnectTimeout(4, TimeUnit.SECONDS)
                .setKeepAlive(true)
                .setEventLoopGroup(socketPool)
                .setAddressController(addressController)
                .build();
    }

    public IAMImpl(int port, @Nonnull String baseUri) throws Exception
    {
        Checks.notEmpty(baseUri, "Base URI");
        this.baseUri = baseUri.endsWith("/") ? baseUri : baseUri + "/";
        this.jca = buildInstance().awaitReady();
        this.manager = new GlobalAccessManagerImpl(this, SignType.ED25519, 2, 15, TimeUnit.MINUTES, "https://localhost.com");
        this.addressController = JDTBuilder.create(socketPool.next())
                .setDatagramChannelType(NioDatagramChannel.class)
                .build();
        this.socketManager = createWebhookManager();
        this.api = JNTBuilder.create(port)
                .setIdentifierString("IAM")
                .setAddressController(addressController)
                .setEventLoopGroup(socketPool)
                .addEventListeners(new SocketTrackerManagerImpl(tracker))
                .addEventListenerProvider(ClassicReceiveHandlerImpl::new)
                .addEventListeners(new ClockObjectManagerImpl())
                .addEventListeners(new OriginAccessManagerImpl(cors()))
                .addEventListeners(new CacheObjectManagerImpl())
                .addEventListeners(new CookieObjectManagerImpl())

                .addEventListeners(new ContentSecurityOverrideManagerImpl())

                .addEventListeners(new ProofObjectManagerImpl(Clock.systemUTC(), getNonceSecret(), 60, TimeUnit.SECONDS, 15, TimeUnit.SECONDS, true))
                .addEventListeners(new ProofOverrideManagerImpl())
                .addEventListeners(accessSignatureManager)
                .addEventListeners(new SessionCryptoManagerImpl(this))
                .addEventListeners(new SubjectRestRateLimiter(250, 50000, 10, TimeUnit.SECONDS, "user", 1024))
                .addEventListeners(manager)

                .addEventListeners(new DigestAccessManagerImpl())
                .addEventListeners(new DigestObjectManagerImpl())

                .addEventListenerProvider(ClassicIdleObjectManagerImpl::new)
                .addEventListenerProvider(ContentEncodingManagerImpl::new)
                .addEventListenerProvider(ContentObjectManagerImpl::new)

                .addEventListeners(new AccessEntryActionImpl())

                .addEventListeners(new PermOverrideManagerImpl())

                .addEventListenerProvider(() -> new UserRetrieveActionImpl(this))

                .addEventListenerProvider(() -> new SelfUserCreateActionImpl(this))
                .addEventListenerProvider(() -> new SelfUserRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new SelfUserDeleteActionImpl(this))
                .addEventListenerProvider(() -> new SelfUserEditActionImpl(this))

                .addEventListenerProvider(() -> new SessionPaginationActionImpl(this))
                .addEventListenerProvider(() -> new SessionRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new SessionCreateActionImpl(this))
                .addEventListenerProvider(() -> new SessionEditActionImpl(this))
                .addEventListenerProvider(() -> new SessionUpdateActionImpl(this))
                .addEventListenerProvider(() -> new SessionDeleteActionImpl(this))
                .addEventListenerProvider(() -> new SessionLogoutActionImpl(this))

                .addEventListenerProvider(() -> new ApplicationCreateActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationPaginationActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationEditActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationDeleteActionImpl(this))

                .addEventListenerProvider(() -> new ApplicationInteractionCreateActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationInteractionOverrideActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationInteractionDeleteActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationInteractionRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new PermissionOverrideUpdateActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationInteractionCallbackActionImpl(this))

                .addEventListenerProvider(() -> new PermissionOverridePaginationActionImpl(this))
                .addEventListenerProvider(() -> new PermissionOverrideRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new PermissionOverrideEditActionImpl(this))
                .addEventListenerProvider(() -> new PermissionOverrideDeleteActionImpl(this))

                .addEventListenerProvider(() -> new WebhookCreateActionImpl(this))
                .addEventListenerProvider(() -> new WebhookPaginationActionImpl(this))
                .addEventListenerProvider(() -> new WebhookRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new WebhookEditActionImpl(this))
                .addEventListenerProvider(() -> new WebhookDeleteActionImpl(this))

                .addEventListeners(new WebhookOverrideManagerImpl(this))
                .addEventListeners(new ErrorObjectManagerImpl(true, 10))
                .build();
    }

    @Nonnull
    public JNTImpl getJNT()
    {
        return (JNTImpl) api;
    }

    @Nonnull
    @Override
    public GlobalAccessManager getAccessManager()
    {
        return manager;
    }

    @Nonnull
    @Override
    public JCA getJCA()
    {
        return jca;
    }

    @Nonnull
    @Override
    public EntityBuilder getEntityBuilder()
    {
        return entityBuilder;
    }

    @Nonnull
    public AccessSignatureManager getAccessSignatureManager()
    {
        return accessSignatureManager;
    }

    @Nonnull
    @Override
    public SocketManager getSocketManager()
    {
        return socketManager;
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<User> retrieveUserById(@Nonnull UUID id)
    {
        Checks.notNull(id, "User ID");
        return new InteractionContextActionImpl<>(getJCA(), "SELECT * FROM users.accounts WHERE user_id = ?", Collections.singletonList(id))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<User> request, @Nonnull BufferArray array)
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    request.onSuccess(entityBuilder.createUser(array.getObject(0)));
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_USER));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Session> retrieveSessionById(@Nonnull UUID userId, @Nonnull UUID sessionId)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(sessionId, "Session ID");
        return new InteractionContextActionImpl<>(getJCA(), "SELECT * FROM users.sessions WHERE user_id = ? AND session_id = ?", Arrays.asList(userId, sessionId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<Session> request, @Nonnull BufferArray array)
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    request.onSuccess(getEntityBuilder().createSession(array.getObject(0)));
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Webhook> retrieveWebhookById(@Nonnull UUID userId, @Nonnull UUID webhookId)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(webhookId, "Webhook ID");
        return new InteractionContextActionImpl<>(getJCA(), "SELECT * FROM users.webhooks WHERE owner_id = ? AND webhook_id = ?", Arrays.asList(userId, webhookId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<Webhook> request, @Nonnull BufferArray array)
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    request.onSuccess(getEntityBuilder().createWebhook(array.getObject(0)));
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_WEBHOOK));
            }
        };
    }

    @Nonnull
    public String getBaseUri()
    {
        return baseUri;
    }

    @Nonnull
    public String getIdentifierString()
    {
        return ((JNTImpl) api).getIdentifierString();
    }

    @Nonnull
    public JDT getJDT()
    {
        return addressController;
    }

    public void shutdown()
    {
        getJDT().close();
        getJNT().shutdown();
        try
        {
            getJNT().awaitShutdown(30, TimeUnit.SECONDS);
        }
        catch (InterruptedException ex)
        {
            Thread.currentThread().interrupt();
        }
        ((GlobalAccessManagerImpl) getAccessManager()).shutdown();
        getSocketManager().shutdown();
        getJCA().shutdown();
    }
}
