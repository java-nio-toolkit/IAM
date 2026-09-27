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

import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.sessions.SessionRetrieveAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractSessionActionImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class SessionRetrieveActionImpl extends AbstractSessionActionImpl implements SessionRetrieveAction
{
    private static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public SessionRetrieveActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Session.GET_SESSION);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleUniqueId(context, request, new ArrayList<>());
    }

    private void handleUniqueId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull List<ErrorResponseException.SchemaError> schemaErrors)
    {
        AccessObjectData json = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueID(json.getSubject(), request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("session_id", ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, request, json, schemaErrors);
        }
    }

    private void checkUniqueID(String userId, @Nonnull Map<String, String> params)
    {
        String id = params.get("session_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(userId))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The subject value is not uuid.");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"session_id\" value is not uuid.");
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull AccessObjectData json,
                                  @Nonnull List<ErrorResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        UUID userId = UUID.fromString(json.getSubject());
        Map<String, String> params = request.getRoute().getMajorParameters();
        UUID sessionId = UUID.fromString(params.get("session_id"));
        api.retrieveUserById(userId)
                .flatMap(user -> user.retrieveSessionById(sessionId))
                .flatMap(this::retrieveAccessData)
                .queue(session -> handleSuccess(context, session), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<DataObject> retrieveAccessData(@Nonnull Session session)
    {
        return session.retrieveAccess().map(data ->
        {
            DataObject user = DataObject.empty()
                    .put("user_id", session.getUserId())
                    .toData();
            if (Helpers.nonEmpty(session.getUserAgent()))
                user.put("user_agent", session.getUserAgent());
            return DataObject.empty()
                    .put("session_id", session.getUniqueId())
                    .put("user", user)
                    .put("jwk", data)
                    .put("flags", session.getFlagsRaw())
                    .toData();
        });
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull DataObject successObj)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new ArrayListValuedHashMap<>(), body));
    }
}
