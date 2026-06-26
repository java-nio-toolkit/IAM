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

package com.github.reganjohn.iam.restactions.self;

import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.exceptions.ErrorResponseException.SchemaError;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.BuilderExample;
import com.github.reganjohn.iam.EntityBuilder;
import com.github.reganjohn.iam.Routes;
import com.github.reganjohn.iam.ThreadLocalReason;
import com.github.reganjohn.iam.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.utils.users.UserCreateData;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.github.adamorgan.jnt.api.managers.ProofObjectManager.JKT;

public class SelfUserCreateActionImpl extends AbstractSelfUserActionImpl implements SelfUserCreateAction
{
    public static final MediaType MEDIA_TYPE_ACCESS = MediaType.parse("application/dpop+jwt");

    public static final List<String> MAJOR_PARAMETER_NAMES =
            Helpers.listOf("username", "flags");

    private static final String ASSERT_TYPE = ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS;

    public SelfUserCreateActionImpl(@Nonnull BuilderExample api)
    {
        super(api, Routes.Self.CREATE_SELF);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new ErrorResponseException(50036, "Only dictionaries may be used in a DictType");
        else
            handleUser(context, request, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
    }

    private void handleUser(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                            @Nonnull DataObject rawData, @Nonnull List<SchemaError> schemaErrors) throws Exception
    {
        rawData.retain(MAJOR_PARAMETER_NAMES);
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUser(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("username", ex, schemaErrors);
        }
        finally
        {
            handleFlags(context, request, rawData, schemaErrors);
        }
    }

    private void handleFlags(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                             @Nonnull DataObject rawData, @Nonnull List<SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkFlags(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("username", ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, request, rawData, schemaErrors);
        }
    }

    private void checkUser(@Nonnull DataObject body)
    {
        if (!body.hasKey(NAME))
            return;
        else if (!body.isType(NAME, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not string.", NAME));
        else if (body.getString(NAME).length() < MIN_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MIN,
                    Helpers.format("The \"%s\" value may not be less than %f characters.", NAME, MIN_NAME_LENGTH));
        else if (body.getString(NAME).length() > MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"%s\" may not be longer than %d characters.", NAME, MAX_NAME_LENGTH));
    }

    private void checkFlags(DataObject body)
    {
        if (!body.hasKey("flags"))
            return;
        else if (!body.isType("flags", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE,
                    Helpers.format("Value \"%s\" is not number.", NAME));
        else if (body.getInt(NAME) < 0)
            throw new DataObjectParsingException(NUMBER_TYPE_MIN,
                    Helpers.format("flags value should be greater than or equal to 0.", NAME));
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawData, @Nonnull List<SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(50035, "Invalid Form Body", errors);
        else
            handleAccessToken(context, request, rawData);
    }

    private void handleAccessToken(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull DataObject rawBody) throws Exception
    {
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();

        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            String uniqueId = UUIDv7.randomUUID().toString();
            String issuer = api.getJNT().getIdentifierString();
            String subject = UUIDv7.randomUUID().toString();

            AccessOptionData optionData = new AccessOptionData(snapshot.getUniqueId(), ASSERT_TYPE, manager.getSignType());
            AccessObjectData json = EntityBuilder.createObjectData(uniqueId, issuer, subject, manager, contextData, optionData, snapshot);
            onSelfCreate(context, request, contextData, json, data, rawBody);
        }
    }

    private void onSelfCreate(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull AccessContextData contextData, @Nonnull AccessObjectData objectData,
                              @Nonnull ProofObjectData assertData, @Nonnull DataObject content)
    {
        UUID userId = UUID.fromString(objectData.getSubject());
        String name = content.getString("username");
        int flags = content.getInt("flags");
        String thumbprint = contextData.digest();
        AccessEntryData entryData = assertData.getEntryData();
        UUIDv7 sessionId = UUIDv7.nameUUIDFromBytes(entryData.getPublicKey().getEncoded());
        DataObject rawData = objectData.getContextData();
        if (rawData == null)
            throw new IllegalStateException("The confirmation is required option and cannot be missing!");
        else if (!rawData.hasKey(JKT))
            throw new IllegalArgumentException("The thumbprint is required option and cannot be missing!");
        else if (!rawData.isType(JKT, DataType.STRING))
            throw new IllegalArgumentException("The JWK Thumbprint within the confirmation object must be a string!");

        String userAgent = request.getHeaders().get("User-Agent");
        UserCreateData data = new UserCreateData(userId, sessionId.toUUID(), name, userAgent, entryData, flags, thumbprint);
        api.createUser(data).queue(success -> handleSuccess(context, objectData), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull AccessObjectData objectData)
    {
        ByteBuf successObj = ByteBufUtil.writeUtf8(context.alloc(), objectData.getRaw());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_ACCESS, successObj, true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
