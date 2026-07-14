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

package com.github.reganjohn.iam.internal.requests.restactions.self;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
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
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.self.SelfUserCreateAction;
import com.github.reganjohn.iam.api.utils.users.UserCreateData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractUserActionImpl;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class SelfUserCreateActionImpl extends AbstractUserActionImpl implements SelfUserCreateAction
{
    public static final MediaType MEDIA_TYPE_ACCESS = MediaType.parse("application/dpop+jwt");

    public SelfUserCreateActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Self.CREATE_SELF);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (!(request.getBody() instanceof JacksonRequestBody && ((JacksonRequestBody) request.getBody()).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleName(context, request, ((JacksonRequestBody) request.getBody()).getObject(), new ArrayList<>());
    }

    private void handleName(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                            @Nonnull DataObject rawData,
                            @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkName(rawData);
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

    private void checkName(@Nonnull DataObject body)
    {
        if (!body.hasKey("username"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!body.isType("username", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"username\" value is not string.");
        else if (body.getString("username").length() < User.MIN_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MIN,
                    Helpers.format("The \"username\" value may not be less than %f characters.", User.MIN_NAME_LENGTH));
        else if (body.getString("username").length() > User.MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"username\" may not be longer than %d characters.", User.MAX_NAME_LENGTH));
    }

    private void handleFlags(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                             @Nonnull DataObject rawData,
                             @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkFlags(rawData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("flags", ex, schemaErrors);
        }
        finally
        {
            handleSessionFlags(context, request, rawData, rawData.getObject("session", DataObject.empty()), schemaErrors);
        }
    }

    private void checkFlags(@Nonnull DataObject body)
    {
        if (!body.hasKey("flags"))
            return;
        else if (!body.isType("flags", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE, "Value \"flags\" is not number.");
        else if (body.getInt("flags") < 0)
            throw new DataObjectParsingException(NUMBER_TYPE_MIN,
                    "Value \"flags\" should be greater than or equal to 0.");
    }

    private void handleSessionFlags(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                    @Nonnull DataObject rawData, @Nonnull DataObject sessionData,
                                    @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkSessionFlags(sessionData);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("session.flags", ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, request, rawData, sessionData, schemaErrors);
        }
    }

    private void checkSessionFlags(@Nonnull DataObject body)
    {
        if (!body.hasKey("flags"))
            return;
        else if (!body.isType("flags", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE, "Value \"flags\" is not number.");
        else if (body.getInt("flags") < 0)
            throw new DataObjectParsingException(NUMBER_TYPE_MIN,
                    "Value \"flags\" should be greater than or equal to 0.");
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody, @Nonnull DataObject sessionData,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        AccessEntryManagerImpl.AccessEntrySnapshot snapshot = manager.getCurrentOrder();
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            String uniqueId = UUIDv7.randomUUID().toString();
            String identifier = api.getJNT().getIdentifierString();
            UUIDv7 userId = UUIDv7.randomUUID();
            AccessOptionData optionData = new AccessOptionData(snapshot.getName(), ProofOverrideManagerImpl.MEDIA_TYPE_ACCESS, manager.getSignType());
            AccessObjectData json = EntityBuilder.createObjectData(uniqueId, identifier, userId.toString(), manager, contextData, optionData, snapshot);
            handleInternally(context, request, userId.toUUID(), contextData, json, data, rawBody, sessionData);
        }
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull UUID userId, @Nonnull AccessContextData contextData,
                                  @Nonnull AccessObjectData objectData, @Nonnull ProofObjectData assertData,
                                  @Nonnull DataObject rawData, @Nonnull DataObject sessionData)
    {
        String name = rawData.getString("username");
        String thumbprint = contextData.digest();
        AccessEntryData entryData = assertData.getEntryData();
        byte[] rawPublicKey = entryData.getPublicKey().getEncoded();
        UUID sessionId = UUIDv7.nameUUIDFromBytes(rawPublicKey).toUUID();
        String agent = request.getHeaders().get("User-Agent");
        int userFlags = rawData.getInt("flags", 0) & ~User.UserFlag.SYSTEM;
        int sessionFlags = sessionData.getInt("flags", 0) & ~Session.SessionFlag.SYSTEM;
        UserCreateData data = new UserCreateData(userId, sessionId, name, agent, entryData, userFlags, sessionFlags, thumbprint);
        api.createUser(data).queue(success -> handleSuccess(context, objectData), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull AccessObjectData objectData)
    {
        ByteBuf successObj = ByteBufUtil.writeUtf8(context.alloc(), objectData.getRaw());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_ACCESS, successObj, true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
