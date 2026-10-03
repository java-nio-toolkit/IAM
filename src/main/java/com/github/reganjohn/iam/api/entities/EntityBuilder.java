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
import com.github.adamorgan.jnt.api.managers.ProofObjectManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationCallbackResponse;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.entities.*;
import com.github.reganjohn.iam.internal.interactions.ApplicationCallbackResponseImpl;
import com.github.reganjohn.iam.internal.interactions.ApplicationContextInteractionImpl;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.api.utils.data.BufferObject;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
import java.util.*;

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
        OffsetDateTime expiresAt = offset.plus(manager.getTimeoutDuration());
        List<String> audiences = manager.getAudiences();
        DataObject actor = rawActor != null ? Helpers.singletonData("sub", rawActor) : null;
        AccessOptionData optionData = new AccessOptionData(snapshot.getUniqueId(), type, manager.getSignType(), snapshot);
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
        String header = IOUtil.encodeURL(optionData);
        String payload = IOUtil.encodeURL(rawData);

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
    public UserImpl createUser(BufferObject data)
    {
        UUID userId = data.getUUID("user_id");
        String username = data.getString("username");
        String avatarId = data.getString("avatar_id", null);
        long flags = data.getLong("flags");
        return new UserImpl(api, userId, username, avatarId, flags);
    }

    @Nonnull
    public List<Session> createSessions(@Nonnull BufferArray data)
    {
        List<Session> sessions = new ArrayList<>();
        for (BufferObject obj : data)
            if (nonDelete(obj))
                sessions.add(createSession(obj));
        return sessions;
    }

    @Nonnull
    public SessionImpl createSession(@Nonnull BufferObject data)
    {
        UUID userId = data.getUUID("user_id");
        UUID sessionId = data.getUUID("session_id");
        long flags = data.getLong("flags");
        String userAgent = data.getString("user_agent", null);
        String thumbprint = data.getString("thumbprint");
        return new SessionImpl(api, userId, sessionId, flags, thumbprint, userAgent);
    }

    @Nonnull
    public AccessEntryArray createAccessEntries(@Nonnull BufferArray data) throws Exception
    {
        List<AccessEntryData> set = new ArrayList<>();
        for (BufferObject obj : data)
            if (nonDelete(obj))
                set.add(createAccessEntry(obj));
        return new AccessEntryArray(set);
    }

    @Nonnull
    public static AccessEntryData createAccessEntry(@Nonnull BufferObject data) throws Exception
    {
        String id = data.getString("kid", null);
        byte[] publicKey = data.getBytes("public_key");
        String type = data.getString("kty");
        String alg = data.getString("alg");
        SignType signType = SignType.from(alg);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(getAlgorithm(AccessEntryType.valueOf(type), alg), "BC");
        PublicKey key = keyFactory.generatePublic(keySpec);
        DataObject rawData = createAccessSecretData(AccessEntryType.valueOf(type), new KeyPair(key, null), true);
        DataObject rawEntryData = DataObject.empty()
                .put("alg", alg)
                .put("kty", type)
                .toData();
        if (id != null)
            rawEntryData.put("kid", id);
        String usage = data.getString("usage", null);
        if (usage != null)
            rawData.put("use", usage);
        rawEntryData.putAll(rawData);
        return createAccessEntry(id, signType, rawEntryData);
    }

    @Nonnull
    private static String getAlgorithm(@Nonnull AccessEntryType type, @Nonnull String alg)
    {
        switch (type)
        {
            case EC:
                return "EC";
            case RSA:
                return "RSA";
            default:
                return alg;
        }
    }

    @Nonnull
    public List<Application> createApplications(@Nonnull BufferArray data)
    {
        List<Application> applications = new ArrayList<>();
        for (BufferObject obj : data)
            if (nonDelete(obj))
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
        String origin = data.getString("origin");
        long flags = data.getLong("flags");
        List<String> redirectUris = data.getList(String.class, "redirect_uris");
        return new ApplicationImpl(api, applicationId, ownerId, name, description, iconId, origin, flags, redirectUris);
    }

    @Nonnull
    public List<Webhook> createWebhooks(@Nonnull BufferArray data)
    {
        List<Webhook> webhooks = new ArrayList<>();
        for (BufferObject obj : data)
            if (nonDelete(obj))
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
        String url = data.getString("endpoint");
        OffsetDateTime updatedAt = Helpers.toOffsetDateTime(data.getTimestamp("updated_at"));
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
        long rawPermissions = data.getLong("permissions");
        OffsetDateTime expiresAt = Helpers.toOffsetDateTime(data.getTimestamp("expiry"));
        String uri = data.getString("redirect_uri");
        String clientNonce = data.getString("nonce");
        String finishNonce = data.getString("finish");
        String hashMethod = data.getString("method_hash");
        String grantUri = data.getString("uri");
        String continueHash = data.getString("hash");
        DataObject accessRaw = DataObject.fromJson(data.getString("access_raw"));
        String label = data.getString("label", null);
        return new ApplicationContextInteractionImpl(api, ownerId, applicationId, interactionId, expiresAt, rawPermissions, uri,
                clientNonce, finishNonce, hashMethod, grantUri, continueHash, accessRaw, label);
    }

    @Nonnull
    public ApplicationCallbackResponse createContextResponse(@Nonnull BufferObject data)
    {
        UUID userId = data.getUUID("user_id");
        UUID ownerId = data.getUUID("owner_id");
        UUID applicationId = data.getUUID("application_id");
        UUID interactionId = data.getUUID("interaction_id");
        long rawPermissions = data.getLong("permissions");
        String reference = data.getString("reference");
        String continueHash = data.getString("hash");
        DataObject accessRaw = DataObject.fromJson(data.getString("access_raw"));
        String thumbprint = data.getString("thumbprint");
        String label = data.getString("label", null);
        boolean denied = data.getBoolean("denied", false);
        return new ApplicationCallbackResponseImpl(api, userId, ownerId, applicationId, interactionId, rawPermissions,
                reference, continueHash, accessRaw, thumbprint, label, denied);
    }

    @Nonnull
    public List<PermissionOverride> createPermissionOverrides(@Nonnull BufferArray data)
    {
        List<PermissionOverride> overrides = new ArrayList<>();
        for (BufferObject obj : data)
            if (nonDelete(obj))
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
            if (isDelete(obj))
                return true;
        }
        return false;
    }

    public static boolean isDelete(@Nonnull BufferObject obj)
    {
        return (obj.getLong("flags", 0) & DELETED) != 0;
    }

    public static boolean nonDelete(@Nonnull BufferObject obj)
    {
        return !isDelete(obj);
    }

    public static long count(@Nonnull BufferArray array)
    {
        return array.stream().filter(EntityBuilder::nonDelete).count();
    }
}
