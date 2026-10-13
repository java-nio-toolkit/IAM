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

package com.github.reganjohn.iam.internal.requests.restactions.sessions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.sessions.SessionEditAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.api.utils.sessions.SessionEditBuilder;
import com.github.reganjohn.iam.api.utils.sessions.SessionEditData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractSessionActionImpl;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.c4j.internal.utils.InteractionUtil;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class SessionEditActionImpl extends AbstractSessionActionImpl implements SessionEditAction
{
    public SessionEditActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Session.EDIT_SESSION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        RequestBody body = request.getBody();
        if (!(body instanceof JacksonRequestBody && ((JacksonRequestBody) body).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleUniqueID(context, request, ((JacksonRequestBody) body).getObject(), new ArrayList<>());
    }

    private void handleUniqueID(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull DataObject json,
                                @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueID(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("session_id", ex, schemaErrors);
        }
        finally
        {
            handleUserAgent(context, request, json, schemaErrors);
        }
    }

    private void checkUniqueID(@Nonnull Map<String, String> params)
    {
        String id = params.get("session_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"session_id\" value is not uuid.");
    }

    private void handleUserAgent(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject json,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors) throws Exception
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUserAgent(json);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("user_agent", ex, schemaErrors);
        }
        finally
        {
            handleFlags(context, request, json, schemaErrors);
        }
    }

    private void checkUserAgent(@Nonnull DataObject json)
    {
        if (!json.hasKey("user_agent"))
            return;
        else if (!json.isType("user_agent", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"user_agent\" value is not string.");
        else if (json.isEmpty("user_agent"))
            throw new DataObjectParsingException(STRING_TYPE_MIN, "The \"user_agent\" value may not be empty.");
        else if (json.getString("user_agent").length() > User.MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"user_agent\" value may not be longer than %d characters.", User.MAX_NAME_LENGTH));
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
            handleInternally(context, request, rawData, schemaErrors);
        }
    }

    private void checkFlags(@Nonnull DataObject body)
    {
        if (!body.hasKey("flags"))
            return;
        else if (!body.isType("flags", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE, "Value \"flags\" is not number.");
        else if (body.getInt("flags") < 0)
            throw new DataObjectParsingException(NUMBER_TYPE_MIN, "Value \"flags\" should be greater than or equal to 0.");
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        ProofObjectData data = retrieveSelfProof(context);
        UUID userId = retrieveSelfUserId(context);
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            UUID sessionId = UUID.fromString(request.getRoute().getMajorParameters().get("session_id"));
            api.retrieveSessionById(userId, sessionId)
                    .flatMap(session -> modify(session, fromData(session, rawBody, data, contextData.digest())))
                    .queue(success -> handleSuccess(context), context::fireExceptionCaught);
        }
    }

    @Nonnull
    private SessionEditData fromData(@Nonnull Session session, @Nonnull DataObject json,
                                     @Nonnull ProofObjectData data, @Nonnull String thumbprint)
    {
        UUID sessionId = session.getUniqueId();
        UUID userId = session.getUserId();
        String userAgent = json.getString("user_agent", session.getUserAgent());
        long flags = json.getLong("flags", session.getFlagsRaw());
        long base = session.getFlagsRaw() & Session.SessionFlag.SYSTEM;
        long modifiers = flags & ~Session.SessionFlag.SYSTEM;
        return new SessionEditBuilder()
                .setUserId(userId)
                .setSessionId(sessionId)
                .setUserAgent(userAgent)
                .setAccessEntry(data.getEntryData())
                .setSessionFlags(base | modifiers)
                .setThumbprint(thumbprint)
                .setReplace(true)
                .build();
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> modify(@Nonnull Session session, @Nonnull SessionEditData data)
    {
        Checks.notNull(session, "Session");
        Checks.notNull(data, "SessionEditData");
        InteractionMapping map = new InteractionMapping.Builder(data.toMap())
                .put("current_flags", session.getFlagsRaw())
                .build();
        return new InteractionMappingActionImpl<>(api.getJCA(), ClassLoader.getResourceAsString("edit_session.cql"), map)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION));
            }
        };
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }
}
