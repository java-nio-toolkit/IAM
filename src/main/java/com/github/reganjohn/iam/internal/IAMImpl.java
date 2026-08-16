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

import com.github.adamorgan.jnt.api.ConnectionType;
import com.github.adamorgan.jnt.api.JNT;
import com.github.adamorgan.jnt.api.JNTBuilder;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryType;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.managers.*;
import com.github.adamorgan.jnt.internal.requests.restaction.AccessEntryActionImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.archive.AdaMorganClientV2;
import com.github.reganjohn.iam.internal.managers.ContentSecurityOverrideManagerImpl;
import com.github.reganjohn.iam.internal.managers.ErrorObjectManagerImpl;
import com.github.reganjohn.iam.internal.managers.GlobalAccessManagerImpl;
import com.github.reganjohn.iam.internal.managers.PermOverrideManagerImpl;
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
import com.reganjohn.jact.api.JACT;
import com.reganjohn.jact.api.JACTBuilder;
import com.reganjohn.jact.api.requests.Consistency;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.Compression;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.JACTImpl;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.managers.SecretAccessManagerImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionCreateActionImpl;
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
    private final JACT jact;

    private final EntityBuilder entityBuilder = new EntityBuilder(this);

    public static void main(String[] args) throws Exception
    {
        String host = "localhost";
        int port = 8080;
        new IAMImpl(host, port);
    }

    public static JACT buildInstance()
    {
        return JACTBuilder.create("localhost", 9042)
                .setApplicationName("Test Client")
                .setProtocolVersion(5)
                .addEventListener(new SecretAccessManagerImpl("cassandra", "cassandra"))
                .setCompression(Compression.LZ4)
                .setDefaultConsistency(Consistency.QUORUM)
                .build();
    }

    public IAMImpl(String host, int port) throws Exception
    {
        List<String> audiences = Collections.singletonList("https://localhost.com");
        this.jact = buildInstance();
        this.api = JNTBuilder.create(host, port, ConnectionType.SERVER)
                .addEventListenerProvider(ClassicReceiveHandlerImpl::new)

                .addEventListeners(new ClockObjectManagerImpl())
                .addEventListeners(new OriginAccessManagerImpl())
                .addEventListeners(new CacheObjectManagerImpl())
                .addEventListeners(new CookieObjectManagerImpl())

                .addEventListeners(new ContentSecurityOverrideManagerImpl())
                .addEventListeners(new GlobalAccessManagerImpl(this, SignType.EDDSA, 2, 30, TimeUnit.SECONDS, audiences))
                .addEventListeners(new ProofObjectManagerImpl(60, 15, true))
                .addEventListeners(new ProofOverrideManagerImpl())
                .addEventListeners(new ProofCryptoManagerImpl())
                .addEventListeners(new ProofPresenceManagerImpl())

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

                .addEventListeners(new ErrorObjectManagerImpl(true))
                .build();

        TimeUnit.SECONDS.sleep(2);
        startup();
    }

    public void startup() throws Exception
    {
        try
        {
            String[] statements =
                    {
                            "TRUNCATE global.public_keys",
                            "TRUNCATE integrations.applications",
                            "TRUNCATE integrations.public_keys",
                            "TRUNCATE users.public_keys",
                            "TRUNCATE users.accounts",
                            "TRUNCATE users.sessions",
                            "TRUNCATE users.entitlements"
                    };

            for (String statement : statements)
            {
                new InteractionCreateActionImpl<Void>(jact, statement).queue();
            }

            TimeUnit.SECONDS.sleep(1);
        }
        finally
        {
            //new TestApplicationServer();
            AdaMorganClientV2 clientV2 = new AdaMorganClientV2();
            clientV2.startTest();
        }
    }

    @Nonnull
    public JNTImpl getJNT()
    {
        return (JNTImpl) api;
    }

    @Nonnull
    @Override
    public JACTImpl getJACT()
    {
        return (JACTImpl) jact;
    }

    @Nonnull
    @Override
    public EntityBuilder getEntityBuilder()
    {
        return entityBuilder;
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<User> retrieveUserById(@Nonnull UUID id)
    {
        Checks.notNull(id, "User ID");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM users.accounts WHERE user_id = ?", Collections.singletonList(id))
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
}
