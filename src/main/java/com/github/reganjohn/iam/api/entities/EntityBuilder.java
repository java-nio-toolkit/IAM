/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.api.entities;

import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.api.interactions.AccessContextInteraction;
import com.github.reganjohn.iam.api.interactions.ApplicationCallbackResponse;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.entities.*;
import com.github.reganjohn.iam.internal.interactions.AccessContextInteractionImpl;
import com.github.reganjohn.iam.internal.interactions.ApplicationCallbackResponseImpl;
import com.github.reganjohn.iam.internal.interactions.ApplicationContextInteractionImpl;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.api.utils.data.BufferObject;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class EntityBuilder extends AbstractEntityBuilder
{
    private static final long DELETED = 1L << 34;

    private final IAMImpl api;

    public EntityBuilder(@Nonnull IAMImpl api)
    {
        this.api = api;
    }

    @Nonnull
    public static AccessObjectData createObjectData(@Nonnull String uniqueId, @Nonnull String issuer,
                                                    @Nonnull String subject, @Nonnull AccessEntryManager manager,
                                                    @Nonnull AccessContextData contextData, @Nonnull String type,
                                                    @Nonnull AccessEntryManagerImpl.AccessEntrySnapshot snapshot)
    {
        return createObjectData(uniqueId, issuer, subject, null, null, manager, contextData, type, snapshot);
    }

    @Nonnull
    public static AccessObjectData createObjectData(@Nonnull String uniqueId, @Nonnull String issuer,
                                                    @Nonnull String subject, @Nullable UUID rawActor,
                                                    @Nullable DataArray perm, @Nonnull AccessEntryManager manager,
                                                    @Nonnull AccessContextData contextData, @Nonnull String type,
                                                    @Nonnull AccessEntryManagerImpl.AccessEntrySnapshot snapshot)
    {
        long now = System.currentTimeMillis();
        OffsetDateTime offset = Helpers.toOffset(now);
        OffsetDateTime expiresAt = snapshot.getTimeExpiresAt();
        List<String> audiences = manager.getAudiences();
        DataObject actor = rawActor != null ? Helpers.singletonData("sub", rawActor) : null;
        AccessOptionData optionData = new AccessOptionData(snapshot.getName(), type, manager.getSignType());
        DataObject rawData = DataObject.empty()
                .put("iss", issuer)
                .put("sub", subject);

        if (actor != null)
            rawData.put("act", actor);
        if (perm != null)
            rawData.put("access", perm);

        rawData.put("iat", offset.toEpochSecond())
                .put("exp", expiresAt.toEpochSecond())
                .put("jti", uniqueId)
                .put("cnf", contextData.toData());

        if (Helpers.nonEmpty(audiences))
            rawData.put("aud", audiences.stream().collect(Helpers.toDataArray()));
        String header = IOUtil.encodeURL(optionData.toString().getBytes(StandardCharsets.UTF_8));
        String payload = IOUtil.encodeURL(rawData.toString().getBytes(StandardCharsets.UTF_8));

        try
        {
            byte[] raw = snapshot.sign(header + "." + payload);
            return new AccessObjectData(uniqueId, now, optionData, issuer, subject, actor, raw, contextData.toData(), rawData, 0, expiresAt, audiences);
        }
        catch (Exception error)
        {
            throw new IllegalStateException("Failed to sign access object", error);
        }
    }

    @Nonnull
    public List<AccessContextInteraction> createApplicationAccess(@Nonnull BufferArray array)
    {
        List<AccessContextInteraction> interactions = new ArrayList<>();
        for (BufferObject obj : array)
        {
            interactions.add(createApplicationAccess(obj));
        }
        return interactions;
    }

    @Nonnull
    public AccessContextInteractionImpl createApplicationAccess(@Nonnull BufferObject obj)
    {
        UUID userId = obj.getUUID("user_id");
        UUID ownerId = obj.getUUID("owner_id");
        UUID applicationId = obj.getUUID("application_id");
        UUID accessId = obj.getUUID("access_id");
        long flags = obj.getLong("flags");
        String thumbprint = obj.getString("thumbprint");
        return new AccessContextInteractionImpl(api, userId, ownerId, applicationId, accessId, flags, thumbprint);
    }

    @Nonnull
    public UserImpl createUser(BufferObject data)
    {
        UUID userId = data.getUUID("user_id");
        String username = data.getString("username");
        String avatarId = data.getString("avatar_id", null);
        long flags = data.getInt("flags");
        return new UserImpl(api, userId, username, avatarId, flags);
    }

    @Nonnull
    public List<Session> createSessions(@Nonnull BufferArray data)
    {
        List<Session> sessions = new ArrayList<>();
        for (BufferObject obj : data)
            sessions.add(createSession(obj));
        return sessions;
    }

    @Nonnull
    public SessionImpl createSession(@Nonnull BufferObject data)
    {
        UUID userId = data.getUUID("user_id");
        UUID sessionId = data.getUUID("session_id");
        long flags = data.getInt("flags");
        String userAgent = data.getString("user_agent", null);
        String thumbprint = data.getString("thumbprint");
        return new SessionImpl(api, userId, sessionId, flags, thumbprint, userAgent);
    }

    @Nonnull
    public List<AccessEntryData> createAccessEntries(@Nonnull BufferArray data) throws Exception
    {
        List<AccessEntryData> entries = new ArrayList<>();
        for (BufferObject obj : data)
        {
            entries.add(createAccessEntry(obj));
        }
        return entries;
    }

    @Nonnull
    public AccessEntryData createAccessEntry(@Nonnull BufferObject data) throws Exception
    {
        byte[] publicKey = data.getBytes("public_key");
        String type = data.getString("kty");
        String alg = data.getString("alg");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(alg);
        PublicKey key = keyFactory.generatePublic(keySpec);
        DataObject rawData = AccessEntryKey.fromJSON(type, key);
        DataObject rawEntryData = DataObject.empty()
                .put("kid", data.getString("kid"))
                .put("alg", alg)
                .put("kty", type)
                .put("use", data.getString("usage"))
                .putAll(rawData)
                .toData();
        return createAccessEntry(rawEntryData);
    }

    @Nonnull
    public List<Application> createApplications(@Nonnull BufferArray data)
    {
        List<Application> applications = new ArrayList<>();
        for (BufferObject obj : data)
            applications.add(createApplication(obj));
        return applications;
    }

    @Nonnull
    public ApplicationImpl createApplication(@Nonnull BufferObject data)
    {
        UUID ownerId = data.getUUID("owner_id");
        UUID applicationId = data.getUUID("application_id");
        String name = data.getString("name");
        String description = data.getString("description", null);
        String iconId = data.getString("icon_id", null);
        long flags = data.getInt("flags");
        List<String> redirectUris = data.getList(String.class, "redirect_uris");
        return new ApplicationImpl(api, applicationId, ownerId, name, description, iconId, flags, redirectUris);
    }

    @Nonnull
    public List<Webhook> createWebhooks(@Nonnull BufferArray data)
    {
        List<Webhook> webhooks = new ArrayList<>();
        for (BufferObject obj : data)
            webhooks.add(createWebhook(obj));
        return webhooks;
    }

    @Nonnull
    public Webhook createWebhook(@Nonnull BufferObject data)
    {
        UUID webhookId = data.getUUID("webhook_id");
        String name = data.getString("name");
        UUID ownerId = data.getUUID("owner_id");
        String avatarId = data.getString("avatar_id", null);
        String url = data.getString("url");
        OffsetDateTime updatedAt = Helpers.toOffsetDateTime(data.getTimestamp("expiry"));
        long flags = data.getLong("flags");
        long scopes = data.getLong("scopes");
        return new WebhookImpl(api, webhookId, name, ownerId, avatarId, url, updatedAt, flags, scopes);
    }

    @Nonnull
    public ApplicationContextInteraction createContextInteraction(@Nonnull BufferObject data)
    {
        UUID ownerId = data.getUUID("user_id");
        UUID applicationId = data.getUUID("application_id");
        UUID interactionId = data.getUUID("interaction_id");
        int rawPermissions = data.getInt("permissions");
        OffsetDateTime expiresAt = Helpers.toOffsetDateTime(data.getTimestamp("expiry"));
        String uri = data.getString("redirect_uri");
        return new ApplicationContextInteractionImpl(api, ownerId, applicationId, interactionId, expiresAt, rawPermissions, uri);
    }

    @Nonnull
    public ApplicationCallbackResponse createContextResponse(@Nonnull BufferObject data)
    {
        UUID userId = data.getUUID("user_id");
        UUID ownerId = data.getUUID("owner_id");
        UUID applicationId = data.getUUID("application_id");
        UUID interactionId = data.getUUID("interaction_id");
        int rawPermissions = data.getInt("permissions");
        OffsetDateTime expiresAt = Helpers.toOffsetDateTime(data.getTimestamp("expiry"));
        String uri = data.getString("redirect_uri");
        return new ApplicationCallbackResponseImpl(api, userId, ownerId, applicationId, interactionId, expiresAt, rawPermissions, uri);
    }

    @Nonnull
    public List<PermissionOverride> createPermissionOverrides(@Nonnull BufferArray data)
    {
        List<PermissionOverride> overrides = new ArrayList<>();
        for (BufferObject obj : data)
            overrides.add(createPermissionOverride(obj));
        return overrides;
    }

    @Nonnull
    public PermissionOverrideImpl createPermissionOverride(@Nonnull BufferObject data)
    {
        UUID userId = data.getUUID("user_id");
        UUID applicationId = data.getUUID("application_id");
        UUID ownerId = data.getUUID("owner_id");
        long permissions = data.getLong("permissions");
        long flags = data.getLong("flags");
        OffsetDateTime updatedAt = Helpers.toOffsetDateTime(data.getTimestamp("updated_at"));
        return new PermissionOverrideImpl(api, userId, ownerId, applicationId, permissions, flags, updatedAt);
    }

    public static boolean isDelete(@Nonnull BufferArray array)
    {
        if (array.isEmpty())
            return false;
        for (BufferObject obj : array)
        {
            long flags = obj.getLong("flags", 0);
            if ((flags & DELETED) != 0)
            {
                return true;
            }
        }
        return false;
    }
}
