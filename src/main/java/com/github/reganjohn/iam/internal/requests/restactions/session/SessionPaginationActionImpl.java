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

package com.github.reganjohn.iam.internal.requests.restactions.session;

import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.requests.restactions.session.SessionAction;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.github.reganjohn.iam.api.requests.restactions.UserAction.UUID_TYPE_COERCE;

public class SessionPaginationActionImpl extends AbstractSessionActionImpl
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public SessionPaginationActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Session.GET_SESSIONS);
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
        String subject = json.getSubject();
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueID(subject);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse(SessionAction.SESSION_ID, ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, UUID.fromString(subject), schemaErrors);
        }
    }

    private void checkUniqueID(String userId)
    {
        if (!MiscUtil.isUUID(userId))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The subject value is not uuid.");
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull UUID userId,
                                  @Nonnull List<ErrorResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(50035, "Invalid Form Body", errors);
        api.retrieveSessions(userId)
                
                .map(this::fromJSON)
                .queue(successObj -> handleSuccess(context, successObj), context::fireExceptionCaught);
    }

    @Nonnull
    private DataArray fromJSON(@Nonnull List<Session> sessions)
    {
        return sessions.stream().map(this::fromJSON).collect(Helpers.toDataArray());
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull DataArray successObj)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
