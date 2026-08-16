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
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.webhooks.WebhookCreateAction;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.api.utils.webhooks.WebhookCreateData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractWebhookActionImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class WebhookCreateActionImpl extends AbstractWebhookActionImpl implements WebhookCreateAction
{
    public WebhookCreateActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Webhooks.CREATE_WEBHOOK);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        RequestBody body = request.getBody();
        if (!(body instanceof JacksonRequestBody && ((JacksonRequestBody) body).isObject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_FROM_OBJECT_BODY);
        else
            handleName(context, ((JacksonRequestBody) body).getObject(), new ArrayList<>());
    }

    private void handleName(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody,
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
            handleAvatarId(context, rawBody, errors);
        }
    }

    private void checkName(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("name"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("name", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"name\" value is not string.");
        else if (raw.isEmpty("name"))
            throw new DataObjectParsingException(STRING_TYPE_MIN,
                    Helpers.format("The \"name\" value may not be less than %f characters.", 1));
        else if (raw.getString("name").length() > Webhook.MAX_NAME_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"name\" may not be longer than %d characters.", Webhook.MAX_NAME_LENGTH));
    }

    private void handleAvatarId(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody,
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
            handleUrl(context, rawBody, errors);
        }
    }

    private void checkAvatarId(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("avatar_id"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("avatar_id", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"avatar_id\" value is not string.");
        else if (raw.getString("avatar_id").length() > Webhook.ICON_CID_MAX_LENGTH)
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"avatar_id\" may not be longer than %d characters.", Webhook.ICON_CID_MAX_LENGTH));
    }

    private void handleUrl(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody,
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
            handleScopes(context, rawBody, errors);
        }
    }

    private void checkUrl(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("url"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("url", DataType.STRING))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "Value \"url\" is not string.");
        else if (!MiscUtil.isURL(raw.getString("url"), false))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"url\" is not url.");
        else if (!MiscUtil.isURL(raw.getString("url"), true))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "Value \"url\" is not safe.");
    }

    private void handleScopes(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody,
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
            handleErrorResponse(context, rawBody, errors);
        }
    }

    private void checkScopes(@Nonnull DataObject raw)
    {
        if (!raw.hasKey("scopes"))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!raw.isType("scopes", DataType.INT))
            throw new DataObjectParsingException(NUMBER_TYPE_COERCE, "Value \"scopes\" is not number.");
    }

    private void handleErrorResponse(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody,
                                     @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        if (errors.isEmpty())
            handleInternally(context, rawBody);
        else
            throw new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull DataObject rawBody)
    {
        AccessObjectData data = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        UUID userId = UUID.fromString(data.getSubject());
        WebhookCreateData webhook = fromData(userId, rawBody);
        api.retrieveUserById(userId)
                .flatMap(User::retrieveWebhookCount)
                .flatMap(count -> create(webhook, count))
                .queue(success -> handleSuccess(context), context::fireExceptionCaught);
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> create(@Nonnull WebhookCreateData webhook, int count)
    {
        if (count > 8)
            throw new ErrorResponseException(ErrorResponse.MAX_WEBHOOKS);
        else
            return create(webhook);
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> create(@Nonnull WebhookCreateData webhook)
    {
        Checks.notNull(webhook, "Webhook");
        return new InteractionMappingActionImpl<>(api.getJACT(), ClassLoader.getResourceAsString("create_webhook.cql"), webhook)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.ACCESS_ALREADY_EXISTS));
            }
        };
    }

    @Nonnull
    private WebhookCreateData fromData(@Nonnull UUID userId, @Nonnull DataObject raw)
    {
        UUIDv7 id = UUIDv7.randomUUID();
        String name = raw.getString("name");
        String avatarId = raw.getString("avatar_id", null);
        long scopes = raw.getLong("scopes");
        String url = raw.getString("url");
        long flags = raw.getLong("flags", 0) & ~Webhook.WebhookFlag.SYSTEM;
        OffsetDateTime createdAt = OffsetDateTime.now();
        return new WebhookCreateData(id.toUUID(), name, userId, avatarId, scopes, url, createdAt, flags);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context)
    {
        context.writeAndFlush(new Response(context, StatusReason.CREATED));
    }
}
