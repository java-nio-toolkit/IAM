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

package com.github.reganjohn.iam.internal.managers;

import com.fasterxml.jackson.core.JsonParseException;
import com.github.adamorgan.jnt.api.events.GenericEvent;
import com.github.adamorgan.jnt.api.events.session.InactiveType;
import com.github.adamorgan.jnt.api.events.session.SessionInactiveEvent;
import com.github.adamorgan.jnt.api.exceptions.*;
import com.github.adamorgan.jnt.api.handle.classic.ClassicObjectController;
import com.github.adamorgan.jnt.api.managers.RestRateLimiter;
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.internal.managers.ClassicObjectManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.JNTLogger;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.slf4j.Logger;

import javax.annotation.Nonnull;
import java.io.UnsupportedEncodingException;
import java.net.ProtocolException;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.RejectedExecutionException;

public class ErrorObjectManagerImpl extends ClassicObjectManagerImpl
{
    public static final Logger LOG = JNTLogger.getLog(ErrorObjectManagerImpl.class);

    private static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    private final boolean printStackTrace;
    private final long retryAfter;

    public ErrorObjectManagerImpl(boolean printStackTrace)
    {
        this(printStackTrace, 0);
    }

    public ErrorObjectManagerImpl(boolean printStackTrace, long retryAfter)
    {
        this.printStackTrace = printStackTrace;
        this.retryAfter = retryAfter;
    }

    @Override
    public void exceptionCaught(@Nonnull ChannelHandlerContext context, @Nonnull Throwable error) throws Exception
    {
        Request request = context.channel().attr(Request.IDENTIFIER).get();
        if (error instanceof JsonParseException || error.getCause() instanceof JsonParseException)
            handleFailure(context, ErrorResponse.INVALID_REQUEST_BODY, StatusReason.BAD_REQUEST);
        else if (error instanceof RateLimitedException)
            handleFailure(context, request, (RateLimitedException) error);
        else if (error instanceof ProtocolException)
            handleProtocolFailure(context, error, StatusReason.BAD_REQUEST);
        else if (error instanceof BufferLimitedException)
            handleProtocolFailure(context, error, StatusReason.REQUEST_ENTITY_TOO_LARGE);
        else if (error instanceof UnsupportedEncodingException)
            handleFailure(context, 0, error.getMessage(), StatusReason.UNSUPPORTED_MEDIA_TYPE);
        else if (error instanceof SocketTimeoutException)
            handleProtocolFailure(context, error, StatusReason.REQUEST_TIMEOUT);
        else if (error instanceof RejectedExecutionException)
            handleOverloadFailure(context, error);
        else if (error instanceof InvalidTokenException)
            handleFailure(context, ErrorResponse.INVALID_TOKEN, StatusReason.UNAUTHORIZED);
        else if (error instanceof MissingAccessException)
            handleFailure(context, (MissingAccessException) error);
        else if (error instanceof DetachedEntityException)
            handleFailure(context, 0, error.getMessage(), StatusReason.NOT_FOUND);
        else if (error instanceof InteractionResponseException)
            handleFailure(context, (InteractionResponseException) error);
        else if (error instanceof ErrorResponseException)
            handleFailure(context, (ErrorResponseException) error);
        else if (error instanceof PermissionException)
            handleFailure(context, ErrorResponse.MISSING_ACCESS, StatusReason.FORBIDDEN);
        else if (error instanceof SignatureException)
            handleFailure(context, (SignatureException) error);
        else if (error instanceof GeneralSecurityException)
            handleFailure(context, 0, error.getMessage(), StatusReason.BAD_REQUEST);
        else if (error instanceof IllegalStateException)
            handleFailure(context, 0, error.getMessage(), StatusReason.CONFLICT);
        else if (error instanceof IllegalArgumentException)
            handleFailure(context, 0, error.getMessage(), StatusReason.BAD_REQUEST);
        else if (error instanceof UnsupportedOperationException)
            handleFailure(context, 0, error.getMessage(), StatusReason.BAD_REQUEST);
        else
            handleServerFailure(context, error);
    }

    private void handleServerFailure(@Nonnull ChannelHandlerContext context, @Nonnull Throwable error)
    {
        if (printStackTrace)
            LOG.error("Oops! We've encountered an server error! Not good!", error);
        handleFailure(context, ErrorResponse.SERVER_ERROR, StatusReason.INTERNAL_SERVER_ERROR);
    }

    protected void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull ErrorResponseException errorResponse)
    {
        if (errorResponse.getErrorCode() == ErrorResponse.UNAUTHORIZED.getCode())
            handleFailure(context, errorResponse, StatusReason.UNAUTHORIZED);
        else if (errorResponse.getErrorCode() == ErrorResponse.INVALID_FORM_URL.getCode())
            handleFailure(context, errorResponse, StatusReason.UNPROCESSABLE_ENTITY);
        else if (errorResponse.getErrorCode() == ErrorResponse.INVALID_FORM_BODY.getCode())
            handleFailure(context, errorResponse, StatusReason.UNPROCESSABLE_ENTITY);
        else if (errorResponse.getErrorCode() == ErrorResponse.INVALID_FROM_OBJECT_BODY.getCode())
            handleFailure(context, errorResponse, StatusReason.UNPROCESSABLE_ENTITY);
        else if (errorResponse.getErrorCode() >= 10000 && errorResponse.getErrorCode() < 20000)
            handleFailure(context, errorResponse, StatusReason.NOT_FOUND);
        else if (errorResponse.getErrorCode() >= 20000 && errorResponse.getErrorCode() < 30000)
            handleFailure(context, errorResponse, StatusReason.FORBIDDEN);
        else if (errorResponse.getErrorCode() >= 40000 && errorResponse.getErrorCode() < 50000)
            handleFailure(context, errorResponse, StatusReason.CONFLICT);
        else
            handleFailure(context, errorResponse, StatusReason.BAD_REQUEST);
    }

    private ChannelFuture handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull InteractionResponseException ex)
    {
        DataObject error = DataObject.empty()
                .put("code", ex.getError().getCode())
                .put("meaning", ex.getMeaning())
                .toData();

        DataObject meaning = DataObject.empty()
                .put("code", ex.getErrorCode())
                .put("error", error)
                .toData();
        DataObject raw = Helpers.singletonData("error", meaning);
        
        switch (ex.getError())
        {
            case INVALID_CLIENT:
            case INVALID_CONTINUATION:
                return handleFailure(context, StatusReason.UNAUTHORIZED, raw);
            case UNKNOWN_INTERACTION:
                return handleFailure(context, StatusReason.NOT_FOUND, raw);
            case TOO_MANY_ATTEMPTS:
                return handleFailure(context, StatusReason.TOO_MANY_REQUESTS, raw);
            case INVALID_INTERACTION:
            case USER_DENIED:
            case REQUEST_DENIED:
                return handleFailure(context, StatusReason.FORBIDDEN, raw);
            default:
                return handleFailure(context, StatusReason.BAD_REQUEST, raw);
        }
    }

    private ChannelFuture handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull StatusReason reason, @Nonnull DataObject raw)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, raw.toBinary(), true);
        Response response = new Response(context, reason, new CaseInsensitiveMap<>(), body);
        return context.writeAndFlush(response);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                               @Nonnull RateLimitedException error)
    {
        DataObject json = DataObject.empty()
                .put("message", "You are being rate limited.")
                .put("retry_after", error.getRetryAfter())
                .put("global", true)
                .toData();

        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, json.toBinary(), true);
        Response response = new Response(context, StatusReason.TOO_MANY_REQUESTS, new CaseInsensitiveMap<>(), body);
        context.writeAndFlush(response);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull SignatureException error)
    {
        handleFailure(context, 0, error.getMessage(), StatusReason.UNAUTHORIZED);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull MissingAccessException error)
    {
        ErrorResponseException exception = new ErrorResponseException(50001, error.getMessage());
        handleFailure(context, exception, StatusReason.UNAUTHORIZED);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, ErrorResponse errorResponse,
                               @Nonnull StatusReason reason)
    {
        handleFailure(context, new ErrorResponseException(errorResponse), reason);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, int code, @Nonnull String meaning,
                               @Nonnull StatusReason reason)
    {
        handleFailure(context, new ErrorResponseException(code, meaning), reason);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull ErrorResponseException errorResponse,
                               @Nonnull StatusReason reason)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, errorResponse.getObject().toBinary(), true);
        Response response = new Response(context, reason, new CaseInsensitiveMap<>(), body);
        context.writeAndFlush(response);
    }

    private void handleProtocolFailure(@Nonnull ChannelHandlerContext context, @Nonnull Throwable error, @Nonnull StatusReason reason)
    {
        handleProtocolFailure(context, error, reason, new CaseInsensitiveMap<>());
    }

    private void handleOverloadFailure(@Nonnull ChannelHandlerContext context, @Nonnull Throwable error)
    {
        CaseInsensitiveMap<String, Collection<String>> headers = new CaseInsensitiveMap<>();
        if (retryAfter > 0)
            headers.put(RestRateLimiter.RETRY_AFTER_HEADER, Collections.singletonList(String.valueOf(retryAfter)));
        handleProtocolFailure(context, error, StatusReason.SERVICE_UNAVAILABLE, headers);
    }

    private void handleProtocolFailure(@Nonnull ChannelHandlerContext context, @Nonnull Throwable error, @Nonnull StatusReason reason,
                                       @Nonnull CaseInsensitiveMap<String, Collection<String>> headers)
    {
        ErrorResponseException errorResponse = new ErrorResponseException(0, error.getMessage());
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, errorResponse.getObject().toBinary(), true);
        headers.put(ClassicObjectController.CONNECTION, Collections.singletonList(ClassicObjectController.CLOSE));
        Response response = new Response(context, reason, headers, body);
        context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }

    private void onSessionInactive(@Nonnull ChannelHandlerContext context, @Nonnull SessionInactiveEvent event)
    {
        if (event.getType() == InactiveType.IDLE)
            context.close();
        super.onGenericEvent(context, event);
    }

    @Override
    public void onGenericEvent(@Nonnull ChannelHandlerContext context, @Nonnull GenericEvent event)
    {
        if (event instanceof SessionInactiveEvent)
            onSessionInactive(context, (SessionInactiveEvent) event);
        else
            super.onGenericEvent(context, event);
    }

    @Override
    public boolean isSharable()
    {
        return true;
    }
}
