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

package com.github.reganjohn.iam.internal.requests.restactions;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.requests.restactions.ApplicationAction;
import com.github.reganjohn.iam.internal.IAMImpl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class AbstractApplicationActionImpl extends AbstractOverrideActionImpl implements ApplicationAction
{
    protected static final String DEFAULT_HASH_METHOD = "sha-256";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Map<String, String> MODES;

    static
    {
        Map<String, String> modes = new HashMap<>();
        modes.put("sha-256", "SHA-256");
        modes.put("sha-384", "SHA-384");
        modes.put("sha-512", "SHA-512");
        modes.put("sha3-256", "SHA3-256");
        modes.put("sha3-384", "SHA3-384");
        modes.put("sha3-512", "SHA3-512");
        MODES = Collections.unmodifiableMap(modes);
    }

    public AbstractApplicationActionImpl(@Nonnull IAMImpl api, @Nonnull Route route)
    {
        super(api, route);
    }

    protected void checkOwnerId(@Nonnull Map<String, String> params)
    {
        String id = params.get("user_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"user_id\" value is not uuid.");
    }

    protected void checkRedirectUris(@Nonnull DataArray array)
    {
        if (array.isEmpty())
            throw new DataObjectParsingException(BASE_TYPE_MIN_LENGTH, "The \"redirect_uris\" value may not be empty.");
        else if (array.size() > Application.MAX_URL_COUNT)
            throw new DataObjectParsingException(BASE_TYPE_MAX_LENGTH,
                    Helpers.format("Must be %s or fewer in length.", Application.MAX_URL_COUNT));
        else if (!array.allMatch(JsonNode::isTextual))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"redirect_uris\" contains value which is not a string.");
        else if (!array.allMatch(node -> node.textValue().length() <= Application.MAX_URL_LENGTH))
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"redirect_uris\" value may not be longer than %d characters.", Application.MAX_URL_LENGTH));
        else if (!array.allMatch(node -> MiscUtil.isURL(node.textValue(), false)))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "The \"redirect_uris\" contains value which is not a url.");
    }

    @Nonnull
    protected static Collection<String> getModes()
    {
        return MODES.keySet();
    }

    protected static boolean hasMode(@Nullable String mode)
    {
        return Helpers.contains(MODES, mode, false);
    }

    @Nonnull
    protected static String randomToken()
    {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return IOUtil.encodeURL(bytes);
    }

    protected boolean hasModified(@Nonnull String a, @Nonnull String b)
    {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    @Nonnull
    protected static String digest(@Nonnull String method, @Nonnull String value)
    {
        String mode = MODES.get(method);
        if (mode == null)
            throw new IllegalArgumentException("Unsupported hash method");
        try
        {
            MessageDigest instance = MessageDigest.getInstance(mode);
            byte[] raw = instance.digest(value.getBytes(StandardCharsets.US_ASCII));
            return IOUtil.encodeURL(raw);
        }
        catch (NoSuchAlgorithmException exception)
        {
            throw new IllegalStateException(exception);
        }
    }

    @Nonnull
    protected static String digest(@Nonnull String value)
    {
        return digest(DEFAULT_HASH_METHOD, value);
    }

    @Nonnull
    protected static String hash(@Nonnull String method, @Nonnull String clientNonce,
                                 @Nonnull String finishNonce, @Nonnull String interact,
                                 @Nonnull String uri)
    {
        return digest(method, clientNonce + "\n" + finishNonce + "\n" + interact + "\n" + uri);
    }

    @Nullable
    protected static String retrieveBaseUri(@Nonnull Request request)
    {
        String proto = "https";
        String host = Helpers.get(request.getHeaders(), "Host");
        String forwarded = Helpers.get(request.getHeaders(), "Forwarded");
        if (Helpers.nonEmpty(forwarded))
        {
            for (String element : forwarded.split("[;,]"))
            {
                String[] pair = element.trim().split("=", 2);
                if (pair.length != 2)
                    continue;
                String value = pair[1].trim().replace("\"", "");
                if (pair[0].trim().equalsIgnoreCase("proto"))
                    proto = value;
                else if (pair[0].trim().equalsIgnoreCase("host"))
                    host = value;
            }
        }
        return Helpers.isEmpty(host) ? null : proto + "://" + host + "/";
    }
}
