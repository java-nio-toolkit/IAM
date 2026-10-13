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

import com.github.adamorgan.jnt.api.events.Event;
import com.github.adamorgan.jnt.api.events.GenericEvent;
import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.*;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.requestbody.BufferedRequestBody;
import com.github.adamorgan.jnt.internal.managers.ClassicObjectManagerImpl;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.adamorgan.jnt.internal.utils.CallbackContext;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.adamorgan.jnt.internal.utils.JNTLogger;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.Scope;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.events.applications.interactions.GenericInteractionEvent;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionCreateEvent;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionOverrideEvent;
import com.github.reganjohn.iam.api.managers.WebhookOverrideManager;
import com.github.reganjohn.iam.internal.IAMImpl;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundInvoker;
import io.netty.util.concurrent.FutureListener;
import com.github.adamorgan.jnt.api.utils.collection.CaseInsensitiveMap;
import org.slf4j.Logger;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.net.InetAddress;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class WebhookOverrideManagerImpl extends ClassicObjectManagerImpl implements WebhookOverrideManager
{
    public static final Logger LOG = JNTLogger.getLog(WebhookOverrideManagerImpl.class);

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
            onApplicationInteractionCreate((InteractionCreateEvent) event);
        else if (event instanceof InteractionOverrideEvent)
            onApplicationInteractionOverride((InteractionOverrideEvent) event);
        super.onGenericEvent(context, event);
    }

    private void onApplicationInteractionCreate(@Nonnull InteractionCreateEvent event)
    {
        handleInternally(event.getUserId(), Scope.APPLICATION_INTERACTION_CREATE, event);
    }

    private void onApplicationInteractionOverride(@Nonnull InteractionOverrideEvent event)
    {
        handleInternally(event.getUserId(), Scope.APPLICATION_INTERACTION_ACCEPT, event);
    }

    private void handleInternally(@Nonnull UUID userId, @Nonnull Scope scope, @Nonnull Event event)
    {
        api.retrieveUserById(userId)
                .flatMap(User::retrieveWebhooks)
                .map(webhooks -> retrieveWebhooks(webhooks, scope))
                .queue(webhooks -> handleInternally(webhooks, scope, event), this::handleFailure);
    }

    private void handleInternally(@Nonnull List<Webhook> webhooks, @Nonnull Scope scope, @Nonnull Event event)
    {
        for (Webhook webhook : webhooks)
        {
            handleInternally(webhook, fromJSON(webhook, scope, event));
        }
    }

    private void handleInternally(@Nonnull Webhook webhook, @Nonnull DataObject rawData)
    {
        URI uri = URI.create(webhook.getUrl());
        int port = uri.getPort() == -1 ? 443 : uri.getPort();
        Route route = new Route(Method.POST, uri.getRawPath().length() > 1 ? uri.getRawPath().substring(1) : "/");
        Checks.check(uri.getHost() != null, "The URL is not safe.");
        MiscUtil.resolveSafeAddress(api.getJDT(), uri.getHost()).addListener((FutureListener<InetAddress>) future ->
        {
            InetAddress address = future.getNow();
            if (address == null)
                handleFailure(new IllegalArgumentException("The URL is not safe."));
            else
                handleConnect(address, port, route, rawData);
        });
    }

    private void handleConnect(@Nonnull InetAddress address, int port, @Nonnull Route route, @Nonnull DataObject rawData)
    {
        api.getSocketManager().connect(address, port).addListener((ChannelFutureListener) obj ->
        {
            if (obj.isSuccess())
                handleSuccess(obj, route, rawData);
            else
                handleFailure(obj.cause());
        });
    }

    private void handleSuccess(@Nonnull ChannelFuture connect, @Nonnull Route route, @Nonnull DataObject rawData)
    {
        connect.channel().pipeline().addLast(new WebhookActionImpl(route, rawData));
    }

    private void handleFailure(@Nonnull Throwable error)
    {
        LOG.warn("There was an unexpected error while executing a REST request", error);
    }

    @Nonnull
    private static DataObject fromJSON(@Nonnull Webhook webhook, @Nonnull Scope scope, @Nonnull Event event)
    {
        if (event instanceof GenericInteractionEvent)
            return fromJSON(webhook, scope, (GenericInteractionEvent) event);
        else
            return DataObject.empty();
    }

    @Nonnull
    private static DataObject fromJSON(@Nonnull Webhook webhook, @Nonnull Scope scope,
                                       @Nonnull GenericInteractionEvent event)
    {
        return DataObject.empty()
                .put("unique_id", UUIDv7.randomUUID().toString())
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
        return webhooks.stream().filter(webhook -> webhook.hasScope(scope)).collect(Collectors.toList());
    }

    @Override
    public boolean isSharable()
    {
        return true;
    }

    private static class WebhookActionImpl extends RestActionImpl
    {
        private final DataObject rawData;
        private Request request;

        public WebhookActionImpl(@Nonnull Route route, @Nonnull DataObject rawData)
        {
            super(route);
            this.rawData = rawData;
        }

        @Override
        public void handlerAdded(@Nonnull ChannelHandlerContext context)
        {
            LOG.debug("Sending webhook request on route {}", route.getRoute());
            BufferedRequestBody body = new BufferedRequestBody(MEDIA_TYPE_JSON, rawData.toBinary(), true);
            CaseInsensitiveMap<String, String> headers = new CaseInsensitiveMap<>();
            headers.put("Host", Collections.singletonList(IOUtil.getHost(context.channel().remoteAddress())));
            this.request = new Request(context, this, route.compile(), headers, body, Collections.emptyList());
            context.writeAndFlush(request).addListener(future ->
            {
                if (!future.isSuccess())
                    exceptionCaught(context, future.cause());
            });
        }

        @Override
        public void handlerRemoved(@Nonnull ChannelHandlerContext context)
        {
            closeResource();
        }

        private void closeResource()
        {
            if (request != null)
                request.closeResource();
        }

        @Override
        public void handleResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull Response response) throws Exception
        {
            try (CallbackContext<ChannelHandlerContext> resource = new CallbackContext<>(context, ChannelOutboundInvoker::close))
            {
                if (response.isError())
                    handleFailure(context, new InvalidResponseException(response.code, response.message));
                else if (response.code >= 300 && response.code < 400)
                    reject();
                else
                    handleSuccess(request, response);
            }
        }

        @Override
        public void exceptionCaught(@Nonnull ChannelHandlerContext context, @Nonnull Throwable error)
        {
            LOG.warn("There was an unexpected error while executing a REST request", error);
            closeResource();
            context.close();
        }

        private void reject()
        {
            LOG.warn("The webhook requests do not allow the use of redirects.");
        }

        private void handleSuccess(@Nonnull Request request, @Nonnull Response response)
        {
            LOG.debug("The webhook request was successfully finished with status {}", response.code);
        }

        @Override
        public void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull InvalidResponseException ex)
        {
            LOG.warn("The webhook request finished with an fail", ex);
        }
    }
}
