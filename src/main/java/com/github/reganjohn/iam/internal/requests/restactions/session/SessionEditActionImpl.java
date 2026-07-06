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

package com.github.reganjohn.iam.internal.requests.restactions.session;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.utils.jose.*;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.requests.restactions.session.SessionEditAction;
import com.github.reganjohn.iam.api.utils.sessions.SessionEditData;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.reganjohn.iam.api.requests.restactions.UserAction.*;

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
            handleBody(context, request, (JacksonRequestBody) body);
    }

    private void handleBody(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                            @Nonnull JacksonRequestBody body) throws Exception
    {
        handleUniqueID(context, request, body.getObject(), new ArrayList<>());
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
            handleErrorResponse(SESSION_ID, ex, schemaErrors);
        }
        finally
        {
            handleUserAgent(context, request, json, schemaErrors);
        }
    }

    private void checkUniqueID(Map<String, String> params)
    {
        String id = params.get(SESSION_ID);
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, Helpers.format("The \"%s\" value is not uuid.", SESSION_ID));
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
            handleErrorResponse(USER_AGENT, ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, request, json, schemaErrors);
        }
    }

    private void checkUserAgent(@Nonnull DataObject json)
    {
        if (!json.hasKey(USER_AGENT))
            return;
        else if (!json.isType(USER_AGENT, DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE,
                    Helpers.format("The \"%s\" value is not string.", USER_AGENT));
        else if (json.getString(USER_AGENT).length() < MIN_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MIN,
                    Helpers.format("The \"%s\" value may not be less than %f characters.", USER_AGENT, MIN_NAME_LENGTH));
        else if (json.getString(USER_AGENT).length() > MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"%s\" value may not be longer than %f characters.", USER_AGENT, MAX_NAME_LENGTH));
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody,
                                  @Nonnull List<InvalidResponseException.SchemaError> errors) throws Exception
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(50036, "Invalid Form Body", errors);
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            String subject = json.getSubject();
            UUID userId = UUID.fromString(subject);
            String rawSessionId = request.getRoute().getMajorParameters().get(SESSION_ID);
            UUID sessionId = UUID.fromString(rawSessionId);
            int flags = rawBody.getInt("flags", 0);
            String userAgent = request.getHeaders().get(USER_AGENT);
            AccessEntryData entryData = data.getEntryData();
            String thumbprint = contextData.digest();
            SessionEditData session = new SessionEditData(userId, sessionId, userAgent, entryData, flags, thumbprint);
            api.editSession(session).queue(success -> handleSuccess(context), context::fireExceptionCaught);
        }
    }

    public void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT, new CaseInsensitiveMap<>()));
    }
}
