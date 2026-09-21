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
 * See the License for the specific language governing scopes and
 * limitations under the License.
 */

package com.github.reganjohn.iam.internal.requests.restactions.webhooks;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.webhooks.WebhookEditAction;
import com.github.reganjohn.iam.api.utils.webhooks.WebhookEditBuilder;
import com.github.reganjohn.iam.api.utils.webhooks.WebhookEditData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractWebhookActionImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.c4j.internal.utils.InteractionUtil;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class WebhookEditActionImpl extends AbstractWebhookActionImpl implements WebhookEditAction
{
    public WebhookEditActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Webhooks.MODIFY_WEBHOOK);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        RequestBody body = request.getBody();
        if (!(body instanceof JacksonRequestBody && ((JacksonRequestBody) body).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleWebhookId(context, request, ((JacksonRequestBody) body).getObject(), new ArrayList<>());
    }

    private void handleWebhookId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull DataObject rawBody,
                                 @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkWebhookId(request.getRoute().getMajorParameters());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("webhook_id", ex, errors);
        }
        finally
        {
            handleName(context, request, rawBody, errors);
        }
    }

    private void checkWebhookId(@Nonnull Map<String, String> params)
    {
        String id = params.get("webhook_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"webhook_id\" value is not uuid.");
    }

    private void handleName(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawBody,
                              @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkName(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("name", ex, errors);
        }
        finally
        {
            handleAvatarId(context, request, rawBody, errors);
        }
    }

    private void checkName(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("name"))
            return;
        else if (!raw.isType("name", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"name\" value is not string.");
        else if (raw.isEmpty("name"))
            throw new DataObjectParsingException(STRING_TYPE_MIN, "The \"name\" value may not be empty.");
        else if (raw.getString("name").length() > Webhook.MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"name\" may not be longer than %d characters.", Webhook.MAX_NAME_LENGTH));
    }
    
    private void handleAvatarId(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawBody,
                              @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkAvatarId(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("avatar_id", ex, errors);
        }
        finally
        {
            handleUrl(context, request, rawBody, errors);
        }
    }

    private void checkAvatarId(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("avatar_id"))
            return;
        else if (!raw.isType("avatar_id", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"avatar_id\" value is not string.");
        else if (raw.getString("avatar_id").length() > Webhook.ICON_CID_MAX_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"avatar_id\" may not be longer than %d characters.", Webhook.ICON_CID_MAX_LENGTH));
    }
    
    private void handleUrl(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawBody,
                              @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUrl(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("url", ex, errors);
        }
        finally
        {
            handleScopes(context, request, rawBody, errors);
        }
    }

    private void checkUrl(@Nonnull DataObject raw)
    {
        String url = raw.getString("url", null);
        if (!raw.hasKey("url"))
            return;
        else if (!raw.isType("url", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "Value \"url\" is not string.");
        else if (!MiscUtil.isURL(url, false))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"url\" is not url.");
        else if (!MiscUtil.isURL(url, true))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"url\" is not safe.");
        else if (MiscUtil.isUnsafeURL(URI.create(url)))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"url\" is not safe");
    }
    
    private void handleScopes(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                              @Nonnull DataObject rawBody,
                              @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkScopes(rawBody);
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("scopes", ex, errors);
        }
        finally
        {
            handleErrorResponse(context, request, rawBody, errors);
        }
    }

    private void checkScopes(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("scopes"))
            return;
        else if (!raw.isType("scopes", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE, "Value \"scopes\" is not number.");
    }
    
    private void handleErrorResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull DataObject rawBody,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (errors.isEmpty())
            handleInternally(context, request, rawBody);
        else
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject rawBody)
    {
        Map<String, String> params = request.getRoute().getMajorParameters();
        AccessObjectData data = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(data.getSubject());
        UUID webhookId = UUID.fromString(params.get("webhook_id"));
        api.retrieveUserById(userId)
                .flatMap(user -> user.retrieveWebhookById(webhookId))
                .flatMap(entitlement -> modify(entitlement, rawBody))
                .queue(success -> handleSuccess(context));
    }

    @Nonnull
    @CheckReturnValue
    private InteractionCallbackAction<Void> modify(@Nonnull Webhook webhook, @Nonnull DataObject rawBody)
    {
        Checks.notNull(webhook, "Webhook");
        Checks.notNull(rawBody, "Body");
        return new InteractionMappingActionImpl<>(api.getJCA(), "UPDATE users.webhooks SET name = :name, avatar_id = :avatar_id, endpoint = :url, scopes = :scopes, updated_at = :updated_at WHERE owner_id = :owner_id AND webhook_id = :webhook_id IF EXISTS", fromData(webhook, rawBody))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    interaction.onSuccess(null);
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_ENTITLEMENT));
            }
        };
    }

    @Nonnull
    private WebhookEditData fromData(@Nonnull Webhook webhook, @Nonnull DataObject rawBody)
    {
        return new WebhookEditBuilder()
                .setOwnerId(webhook.getOwnerId())
                .setUniqueId(webhook.getUniqueId())
                .setName(rawBody.getString("name", webhook.getName()))
                .setAvatarId(rawBody.getString("avatar_id", webhook.getAvatarId()))
                .setUrl(rawBody.getString("url", webhook.getUrl()))
                .setScopes(rawBody.getLong("scopes", webhook.getScopesRaw()))
                .setFlags(webhook.getFlagsRaw())
                .setTimeUpdated(OffsetDateTime.now())
                .setReplace(true)
                .build();
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.NO_CONTENT));
    }
}
