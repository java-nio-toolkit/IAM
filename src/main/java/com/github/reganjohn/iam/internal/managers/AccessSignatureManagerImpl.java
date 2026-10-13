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

import com.github.adamorgan.jnt.api.exceptions.InvalidTokenException;
import com.github.adamorgan.jnt.api.exceptions.MissingAttributeException;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.managers.ProofObjectManager;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.managers.ProofSignatureManagerImpl;
import com.github.adamorgan.jnt.internal.requests.restaction.AccessEntryActionImpl;
import com.github.adamorgan.jnt.internal.utils.CallbackContext;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.api.managers.AccessSignatureManager;
import com.github.reganjohn.iam.api.requests.Routes;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.security.KeyPair;

public class AccessSignatureManagerImpl extends ProofSignatureManagerImpl implements AccessSignatureManager
{
    public static final AttributeKey<AccessEntryData> CLIENT_ACCESS = AttributeKey.valueOf("client.signature.access");

    @Override
    public void channelRead0(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        if (acceptInboundMessage(request.getRoute().getBaseRoute()))
            context.fireChannelRead(request);
        else
            super.channelRead0(context, request);
    }

    @Override
    public boolean isRequired(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        return acceptInboundMessage(request.getRoute().getBaseRoute()) || super.isRequired(context, request);
    }

    @Nonnull
    @Override
    public KeyPair getSecret(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                             @Nonnull EdwardsMetadata metadata) throws IOException
    {
        Route route = request.getRoute().getBaseRoute();
        if (!acceptInboundMessage(route))
            return super.getSecret(context, request, metadata);
        else if (route == Routes.Session.ADD_SESSION && !Helpers.contains(metadata.getComponents(), ProofObjectManager.AUTHORIZATION, true))
            throw new InvalidTokenException();
        else
            return new KeyPair(retrieveAccess(context).getPublic(), null);
    }

    @Nonnull
    @Override
    public SignType getPreferredMode(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                     @Nonnull EdwardsMetadata metadata) throws IOException
    {
        if (!acceptInboundMessage(request.getRoute().getBaseRoute()))
            return super.getPreferredMode(context, request, metadata);
        else
            return retrieveAccess(context).getMode();
    }

    @Nonnull
    private AccessEntryData retrieveAccess(@Nonnull ChannelHandlerContext context) throws IOException
    {
        AccessEntryData entry = context.channel().attr(CLIENT_ACCESS).get();
        if (entry == null)
            throw new MissingAttributeException(CLIENT_ACCESS);
        else
            return entry;
    }

    @Nonnull
    @Override
    public AccessEntryData verify(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                  @Nonnull DataObject raw)
    {
        AccessEntryData data = createAccessEntry(raw);
        verify(context, request, data);
        return data;
    }

    @Nonnull
    private AccessEntryData createAccessEntry(@Nonnull DataObject raw)
    {
        try
        {
            DataObject rawData = DataObject.empty()
                    .put(ProofObjectManager.ALG, raw.getString(ProofObjectManager.ALG))
                    .put(ProofObjectManager.KEY, raw)
                    .toData();
            return EntityBuilder.createAccessEntry(rawData);
        }
        catch (Exception ex)
        {
            throw new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN);
        }
    }

    @Override
    public void verify(@Nonnull ChannelHandlerContext context, @Nonnull Request request, @Nonnull AccessEntryData data)
    {
        context.channel().attr(AccessSignatureManagerImpl.CLIENT_ACCESS).set(data);
        try (CallbackContext<ChannelHandlerContext> resource = new CallbackContext<>(context, this::cleanup))
        {
            verify(context, request);
        }
        catch (ProofAccessException ex)
        {
            if (Helpers.nonEmpty(ex.getNonce()))
                throw ex;
            throw new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN);
        }
        catch (Exception ex)
        {
            throw new InteractionResponseException(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN);
        }
    }

    private void cleanup(@Nonnull ChannelHandlerContext context)
    {
        context.channel().attr(AccessSignatureManagerImpl.CLIENT_ACCESS).set(null);
    }

    @Override
    protected boolean acceptOutboundMessage(@Nonnull ChannelHandlerContext context, Response response)
    {
        Route.CompiledRoute route = response.getRoute();
        return (route == null || !AccessEntryActionImpl.BASE_ROUTE.equals(route.getBaseRoute())) && super.acceptOutboundMessage(context, response);
    }

    private boolean acceptInboundMessage(@Nonnull Route route)
    {
        return route == Routes.Interactions.CREATE_APPLICATION_INTERACTION || route == Routes.Interactions.EXECUTE_APPLICATION_INTERACTION
                || route == Routes.Session.ADD_SESSION;
    }
}
