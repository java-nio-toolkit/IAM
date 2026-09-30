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

package com.github.reganjohn.iam.internal.requests.restactions.webhooks;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.webhooks.WebhookRetrieveAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractWebhookActionImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class WebhookRetrieveActionImpl extends AbstractWebhookActionImpl implements WebhookRetrieveAction
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");
    
    public WebhookRetrieveActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Webhooks.GET_WEBHOOK);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        handleUniqueID(context, request, new ArrayList<>());
    }

    private void handleUniqueID(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUniqueID(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("webhook_id", ex, schemaErrors);
        }
        finally
        {
            handleException(context, request, schemaErrors);
        }
    }

    private void checkUniqueID(@Nonnull Map<String, String> params)
    {
        String id = params.get("webhook_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"webhook_id\" value is not uuid.");
    }

    private void handleException(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (Helpers.nonEmpty(errors))
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
        else
            handleInternally(context, request);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        AccessObjectData data = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(data.getSubject());
        UUID webhookId = UUID.fromString(request.getRoute().getMajorParameters().get("webhook_id"));
        api.retrieveUserById(userId)
                .flatMap(user -> user.retrieveWebhookById(webhookId))
                .map(Webhook::toData)
                .queue(json -> handleSuccess(context, json), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull DataObject successObj)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
