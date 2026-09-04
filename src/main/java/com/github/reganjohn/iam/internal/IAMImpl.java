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
import com.github.adamorgan.jnt.api.socket.DefaultSocketManagerBuilder;
import com.github.adamorgan.jnt.api.socket.SocketManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryType;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicRequestSendHandlerImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicResponseReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.managers.*;
import com.github.adamorgan.jnt.internal.requests.restaction.AccessEntryActionImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.managers.GlobalAccessManager;
import com.github.reganjohn.iam.archive.AdaMorganClientV2;
import com.github.reganjohn.iam.internal.managers.*;
import com.github.reganjohn.iam.internal.requests.restactions.UserRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.applications.*;
import com.github.reganjohn.iam.internal.requests.restactions.applications.interactions.ApplicationInteractionCreateActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.applications.interactions.ApplicationInteractionOverrideActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.applications.interactions.ApplicationInteractionRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.applications.interactions.ApplicationInteractionUpdateActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.applications.self.PermissionOverrideDeleteActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.applications.self.PermissionOverrideEditActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.applications.self.PermissionOverridePaginationActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.applications.self.PermissionOverrideRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserCreateActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserDeleteActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserEditActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.sessions.*;
import com.github.reganjohn.iam.internal.requests.restactions.webhooks.*;
import com.reganjohn.c4j.api.JCA;
import com.reganjohn.c4j.api.JCABuilder;
import com.reganjohn.c4j.api.requests.Consistency;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.Compression;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.c4j.internal.managers.SecretAccessManagerImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionCreateActionImpl;
import io.netty.util.ResourceLeakDetector;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.security.Security;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class IAMImpl implements IAM
{
    public static final Map<String, List<String>> signTypes = new ConcurrentHashMap<>();

    static
    {
        for (SignType signType : SignType.values())
        {
            if (signType.getType() == AccessEntryType.NONE)
                continue;
            List<String> set = signTypes.computeIfAbsent(signType.getType().name(), __ -> new ArrayList<>());
            set.add(signType.getName());
        }
    }

    static
    {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.DISABLED);
    }

    private final JNT api;
    private final JCA jca;
    private final GlobalAccessManager manager;
    private final SocketManager socketManager;

    private final EntityBuilder entityBuilder = new EntityBuilder(this);

    public static void main(String[] args) throws Exception
    {
        new IAMImpl(8080, false);
    }

    @Nonnull
    private JCA buildInstance()
    {
        return JCABuilder.create("localhost", 9042)
                .setApplicationName("Test Client")
                .setProtocolVersion(5)
                .addEventListener(new SecretAccessManagerImpl("cassandra", "cassandra"))
                .setCompression(Compression.LZ4)
                .setDefaultConsistency(Consistency.QUORUM)
                .build();
    }

    @Nonnull
    private SocketManager createWebhookManager()
    {
        return DefaultSocketManagerBuilder.create()
                .addEventListenerProvider(ClassicRequestSendHandlerImpl::new)
                .addEventListenerProvider(ClassicResponseReceiveHandlerImpl::new)
                .addEventListenerProvider(() -> new ClassicIdleObjectManagerImpl(30, 30, 5))
                .addEventListenerProvider(ProofPresenceManagerImpl::new)
                .addEventListeners(manager)
                .addEventListenerProvider(ContentObjectManagerImpl::new)
                .addEventListenerProvider(DigestObjectManagerImpl::new)
                .setConnectTimeout(10, TimeUnit.SECONDS)
                .setKeepAlive(true)
                .build();
    }

    public IAMImpl(int port, boolean isTest) throws Exception
    {
        List<String> audiences = Collections.singletonList("https://localhost.com");
        this.jca = buildInstance().awaitReady();
        cleanup();
        TimeUnit.SECONDS.sleep(2);
        this.manager = new GlobalAccessManagerImpl(this, SignType.EDDSA, 2, 60, TimeUnit.SECONDS, audiences);
        this.socketManager = createWebhookManager();
        this.api = JNTBuilder.create(port)
                .addEventListenerProvider(ClassicReceiveHandlerImpl::new)
                .addEventListeners(new ClockObjectManagerImpl())
                .addEventListeners(new OriginAccessManagerImpl())
                .addEventListeners(new CacheObjectManagerImpl())
                .addEventListeners(new CookieObjectManagerImpl())

                .addEventListeners(new ContentSecurityOverrideManagerImpl())
                .addEventListeners(new ProofObjectManagerImpl(60, 15, true))
                .addEventListeners(new ProofOverrideManagerImpl())
                .addEventListeners(new ProofCryptoManagerImpl())
                .addEventListeners(new ProofPresenceManagerImpl())
                .addEventListeners(manager)

                .addEventListeners(new DigestAccessManagerImpl())
                .addEventListeners(new DigestObjectManagerImpl())

                .addEventListenerProvider(ClassicIdleObjectManagerImpl::new)
                .addEventListenerProvider(ContentEncodingManagerImpl::new)
                .addEventListenerProvider(ContentObjectManagerImpl::new)
                //.addEventListenerProvider(() -> new SequentialRestRateLimiter(10, 10, TimeUnit.SECONDS, "user"))

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

                .addEventListenerProvider(() -> new ApplicationAccessActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationSyncActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationOverrideActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationRevokeActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationInteractionCreateActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationInteractionOverrideActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationInteractionUpdateActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationInteractionRetrieveActionImpl(this))

                .addEventListenerProvider(() -> new PermissionOverridePaginationActionImpl(this))
                .addEventListenerProvider(() -> new PermissionOverrideRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new PermissionOverrideEditActionImpl(this))
                .addEventListenerProvider(() -> new PermissionOverrideDeleteActionImpl(this))

                .addEventListenerProvider(() -> new WebhookCreateActionImpl(this))
                .addEventListenerProvider(() -> new WebhookPaginationActionImpl(this))
                .addEventListenerProvider(() -> new WebhookRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new WebhookEditActionImpl(this))
                .addEventListenerProvider(() -> new WebhookDeleteActionImpl(this))

                .addEventListeners(new ErrorObjectManagerImpl(false))
                .build();

        if (isTest)
        {
            TimeUnit.SECONDS.sleep(2);
            AdaMorganClientV2 clientV2 = new AdaMorganClientV2();
            clientV2.startTest();
        }
    }

    public void cleanup()
    {
        String[] statements =
                {
                        "TRUNCATE global.public_keys",

                        "TRUNCATE users.public_keys",
                        "TRUNCATE users.accounts",
                        "TRUNCATE users.sessions",
                        "TRUNCATE users.webhooks",
                        "TRUNCATE users.entitlements",

                        "TRUNCATE integrations.applications",
                        "TRUNCATE integrations.interactions",
                        "TRUNCATE integrations.responses",
                        "TRUNCATE integrations.invites",
                        "TRUNCATE integrations.public_keys"
                };

        for (String statement : statements)
        {
            new InteractionCreateActionImpl<Void>(jca, statement).queue();
        }
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
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
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
    public String getIdentifierString()
    {
        return ((JNTImpl) api).getIdentifierString();
    }
}
