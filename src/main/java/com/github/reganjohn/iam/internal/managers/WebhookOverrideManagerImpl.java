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

package com.github.reganjohn.iam.internal.managers;

import com.github.adamorgan.jnt.api.ConnectionType;
import com.github.adamorgan.jnt.api.JNT;
import com.github.adamorgan.jnt.api.JNTBuilder;
import com.github.adamorgan.jnt.api.events.Event;
import com.github.adamorgan.jnt.api.events.GenericEvent;
import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.*;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicRequestSendHandlerImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicResponseReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.managers.*;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.adamorgan.jnt.internal.utils.requestbody.BufferedRequestBody;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.Scope;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.events.applications.interactions.GenericInteractionEvent;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionCreateEvent;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionOverrideEvent;
import com.github.reganjohn.iam.api.managers.WebhookOverrideManager;
import com.github.reganjohn.iam.internal.IAMImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class WebhookOverrideManagerImpl extends ClassicObjectManagerImpl implements WebhookOverrideManager
{
    private static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    private final IAMImpl api;

    public WebhookOverrideManagerImpl(@Nonnull IAM api)
    {
        this.api = (IAMImpl) api;
    }

    @Nonnull
    public IAMImpl getIAM()
    {
        return api;
    }

    @Override
    public void onGenericEvent(@Nonnull ChannelHandlerContext context, @Nonnull GenericEvent event)
    {
        if (event instanceof InteractionCreateEvent)
            onApplicationInteractionCreate(context, (InteractionCreateEvent) event);
        else if (event instanceof InteractionOverrideEvent)
            onApplicationInteractionOverride(context, (InteractionOverrideEvent) event);
        super.onGenericEvent(context, event);
    }

    private void onApplicationInteractionCreate(@Nonnull ChannelHandlerContext context,
                                                @Nonnull InteractionCreateEvent event)
    {
        handleInternally(context, event.getUserId(), Scope.APPLICATION_INTERACTION_CREATE, event);
    }

    private void onApplicationInteractionOverride(@Nonnull ChannelHandlerContext context,
                                                  @Nonnull InteractionOverrideEvent event)
    {
        handleInternally(context, event.getUserId(), Scope.APPLICATION_INTERACTION_ACCEPT, event);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull UUID userId, @Nonnull Scope scope,
                                  @Nonnull Event event)
    {
        api.retrieveUserById(userId)
                .flatMap(User::retrieveWebhooks)
                .map(webhooks -> retrieveWebhooks(webhooks, scope))
                .queue(webhooks -> handleInternally(context, webhooks, scope, event), this::handleFailure);
    }

    private void handleInternally(@Nonnull ChannelHandlerContext context, @Nonnull List<Webhook> webhooks,
                                  @Nonnull Scope scope, @Nonnull Event event)
    {
        for (Webhook webhook : webhooks)
        {
            handleSuccess(context, webhook, fromJSON(webhook, scope, event));
        }
    }

    private void handleSuccess(ChannelHandlerContext context, @Nonnull Webhook webhook, @Nonnull DataObject rawData)
    {
        connect(context, URI.create(webhook.getUrl()), rawData);
    }

    private void handleFailure(@Nonnull Throwable failure)
    {
        //todo: handle failure
    }

    @Nonnull
    private static DataObject fromJSON(@Nonnull Webhook webhook, @Nonnull Scope scope, @Nonnull Event event)
    {
        if (event instanceof InteractionCreateEvent)
            return fromJSON(webhook, scope, (InteractionCreateEvent) event);
        else
            return DataObject.empty();
    }

    @Nonnull
    private static DataObject fromJSON(@Nonnull Webhook webhook, @Nonnull Scope scope,
                                       @Nonnull GenericInteractionEvent event)
    {
        return DataObject.empty()
                .put("unique_id", UUIDv7.randomUUID())
                .put("webhook_id", webhook.getUniqueId())
                .put("scope", scope.getOffset())
                .put("interaction", event.getRawData())
                .put("timestamp", System.currentTimeMillis())
                .toData();
    }

    @Nonnull
    @CheckReturnValue
    private List<Webhook> retrieveWebhooks(@Nonnull List<Webhook> webhooks, @Nonnull Scope scope)
    {
        return webhooks.stream().filter(webhook -> webhook.getScopes().contains(scope)).collect(Collectors.toList());
    }

    @Nonnull
    public JNT connect(@Nonnull ChannelHandlerContext context, @Nonnull URI uri, @Nonnull DataObject rawData)
    {
        AccessEntryManager manager = context.channel().attr(AccessEntryManagerImpl.IDENTIFIER).get();
        Route route = new Route(Method.POST, uri.getPath().split("/")[1]);
        return JNTBuilder.create(uri.getHost(), 443, ConnectionType.CLIENT)
                .addEventListenerProvider(ClassicRequestSendHandlerImpl::new)
                .addEventListenerProvider(ClassicResponseReceiveHandlerImpl::new)
                .addEventListenerProvider(() -> new ClassicIdleObjectManagerImpl(4, 15, 5))
                .addEventListenerProvider(() -> new SignatureManagerImpl(manager))
                .addEventListenerProvider(LocationObjectManagerImpl::new)
                .addEventListenerProvider(ContentObjectManagerImpl::new)
                .addEventListenerProvider(DigestObjectManagerImpl::new)
                .addEventListenerProvider(() -> new WebhookActionImpl(route, rawData))
                .build();
    }

    @Override
    public boolean isSharable()
    {
        return true;
    }

    private static class WebhookActionImpl extends RestActionImpl
    {
        private final DataObject rawData;

        public WebhookActionImpl(@Nonnull Route route, @Nonnull DataObject rawData)
        {
            super(route);
            this.rawData = rawData;
        }

        @Override
        public void channelActive(ChannelHandlerContext context)
        {
            onRawData(context);
        }

        public void onRawData(@Nonnull ChannelHandlerContext context)
        {
            BufferedRequestBody body = new BufferedRequestBody(MEDIA_TYPE_JSON, rawData.toBinary(), true);
            context.writeAndFlush(new Request(context, route.compile(), new CaseInsensitiveMap<>(), body));
        }

        @Override
        public void handleResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull Response response)
        {
            if (response.isError())
                handleFailure(context, new InvalidResponseException(response.code, response.message));
            else;
                //todo: ...
        }

        @Override
        public void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull InvalidResponseException ex)
        {
            //todo: ...
        }
    }
}
