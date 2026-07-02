/*
 * Copyright 2026 Ada Morgan, John Regan and the JNT contributors
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
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryKey;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.AccessOptionData;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.internal.entities.SessionImpl;
import com.github.reganjohn.iam.internal.entities.UserImpl;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.api.utils.data.BufferObject;

import javax.annotation.Nonnull;
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
    @Nonnull
    public static AccessObjectData createObjectData(@Nonnull String uniqueId, @Nonnull String issuer,
                                                    @Nonnull String subject, @Nonnull AccessEntryManager manager,
                                                    @Nonnull AccessContextData contextData,
                                                    @Nonnull AccessOptionData optionData,
                                                    @Nonnull AccessEntryManagerImpl.AccessEntrySnapshot snapshot)
            throws Exception
    {
        long now = System.currentTimeMillis();
        OffsetDateTime offset = Helpers.toOffset(now);
        OffsetDateTime expiresAt = snapshot.getTimeExpiresAt();
        List<String> audiences = manager.getAudiences();
        DataObject rawData = DataObject.empty()
                .put("iss", issuer)
                .put("sub", subject)
                .put("iat", offset.toEpochSecond())
                .put("exp", expiresAt.toEpochSecond())
                .put("jti", uniqueId)
                .put("cnf", contextData.toData());
        if (Helpers.nonEmpty(audiences))
            rawData.put("aud", audiences.stream().collect(Helpers.toDataArray()));
        String header = IOUtil.encodeURL(optionData.toString().getBytes(StandardCharsets.UTF_8));
        String payload = IOUtil.encodeURL(rawData.toString().getBytes(StandardCharsets.UTF_8));
        byte[] raw = snapshot.sign(header + "." + payload);
        return new AccessObjectData(uniqueId, now, optionData, issuer, subject, raw, contextData.toData(), 0, expiresAt, audiences);
    }

    @Nonnull
    public static UserImpl createUser(BufferObject data)
    {
        UUID userId = data.getUUID("user_id");
        String username = data.getString("username");
        int flags = data.getInt("flags");
        return new UserImpl(userId, username, flags);
    }

    @Nonnull
    public static List<Session> createSessions(@Nonnull BufferArray data) throws Exception
    {
        List<Session> sessions = new ArrayList<>();
        for (BufferObject obj : data)
            sessions.add(createSession(obj));
        return sessions;
    }

    @Nonnull
    public static SessionImpl createSession(@Nonnull BufferObject data) throws Exception
    {
        UUID userId = data.getUUID("user_id");
        UUID sessionId = data.getUUID("session_id");
        int flags = data.getInt("flags");
        String userAgent = data.getString("user_agent", null);
        String thumbprint = data.getString("thumbprint");
        byte[] publicKey = data.getBytes("public_key");
        String type = data.getString("kty");
        String alg = data.getString("alg");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(alg);
        PublicKey key = keyFactory.generatePublic(keySpec);
        DataObject rawData = AccessEntryKey.fromJSON(type, key);
        DataObject rawEntryData = DataObject.empty()
                .put("kid",  data.getString("kid"))
                .put("alg", alg)
                .put("kty", type)
                .put("use", data.getString("usage"))
                .putAll(rawData)
                .toData();
        return new SessionImpl(userId, sessionId, flags, thumbprint, createAccessEntry(rawEntryData), userAgent);
    }
}
