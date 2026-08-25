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
import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryType;
import com.github.adamorgan.jnt.internal.managers.ClassicObjectManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.adamorgan.jnt.internal.utils.JNTLogger;
import com.github.adamorgan.jnt.internal.utils.responsebody.BufferedResponseBody;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.slf4j.Logger;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

public class ErrorObjectManagerImpl extends ClassicObjectManagerImpl
{
    public static final Logger LOG = JNTLogger.getLog(ErrorObjectManagerImpl.class);

    private static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    private static final String ERROR_AUTHORIZATION = "WWW-Authenticate";

    private final boolean printStackTrace;

    public ErrorObjectManagerImpl(boolean printStackTrace)
    {
        this.printStackTrace = printStackTrace;
    }

    @Override
    public void exceptionCaught(@Nonnull ChannelHandlerContext context, @Nonnull Throwable error) throws Exception
    {
        Request request = context.channel().attr(Request.IDENTIFIER).get();
        if (printStackTrace)// && !(error instanceof MissingAccessException))
            LOG.error("Oops! We've encountered an server error! Not good!", error);

        if (error instanceof JsonParseException)
            handleFailure(context, ErrorResponse.INVALID_REQUEST_BODY, StatusReason.BAD_REQUEST);
        else if (error instanceof RateLimitedException)
            handleFailure(context, request, (RateLimitedException) error);
        else if (error instanceof ProofAccessException)
            handleFailure(context, (ProofAccessException) error);
        else if (error instanceof InvalidTokenException)
            handleFailure(context, ErrorResponse.INVALID_TOKEN, StatusReason.UNAUTHORIZED);
        else if (error instanceof MissingAccessException)
            handleFailure(context, (MissingAccessException) error);
        else if (error instanceof DetachedEntityException)
            handleFailure(context, 0, error.getMessage(), StatusReason.NOT_FOUND);
        else if (error instanceof ErrorResponseException)
            handleFailure(context, (ErrorResponseException) error);
        else if (error instanceof PermissionException)
            handleFailure(context, ErrorResponse.MISSING_ACCESS, StatusReason.FORBIDDEN);
        else if (error instanceof SignatureException)
            handleFailure(context, (SignatureException) error);
        else if (error instanceof IllegalStateException)
            handleFailure(context, 0, error.getMessage(), StatusReason.CONFLICT);
        else if (error instanceof IllegalArgumentException)
            handleFailure(context, 0, error.getMessage(), StatusReason.BAD_REQUEST);
        else if (error instanceof IOException)
            handleFailure(context, 0, error.getMessage(), StatusReason.INTERNAL_SERVER_ERROR);
        else
            super.exceptionCaught(context, error);
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

    private void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull ProofAccessException error)
    {
        Map<String, String> headers = new HashMap<>();

        if (Helpers.nonEmpty(error.getNonce()))
            headers.put("DPoP-Nonce", error.getNonce());

        handleProofAccess(headers, error);
        ErrorResponseException exception = new ErrorResponseException(50001, error.getMessage());
        handleFailure(context, exception, headers, StatusReason.UNAUTHORIZED);
    }

    private void handleProofAccess(@Nonnull Map<String, String> headers, @Nonnull ProofAccessException error)
    {
        StringBuilder builder = new StringBuilder(error.getType());
        appendTo(builder, "realm", error.getScope());
        appendTo(builder, "algs", getAllowModes());
        if (Helpers.nonEmpty(error.getCode()))
            appendTo(builder, "error", error.getCode());
        if (Helpers.nonEmpty(error.getMeaning()))
            appendTo(builder, "error_description", error.getMeaning());
        if (Helpers.nonEmpty(error.getNonce()))
            appendTo(builder, "next_nonce", error.getNonce());
        headers.put(ERROR_AUTHORIZATION, builder.toString());
    }

    private void appendTo(StringBuilder builder, String key, String value)
    {
        if (builder.indexOf(" ") != -1)
            builder.append(",");
        builder.append(" ")
                .append(key)
                .append("=\"")
                .append(value)
                .append("\"");
    }

    @Nonnull
    private String getAllowModes()
    {
        StringJoiner joiner = new StringJoiner(" ");
        for (SignType type : SignType.values())
        {
            if (type.getType() != AccessEntryType.NONE)
                joiner.add(type.getName());
        }
        return joiner.toString();
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull MissingAccessException error)
    {
        ErrorResponseException exception = new ErrorResponseException(50001, error.getMessage());
        handleFailure(context, exception, StatusReason.UNAUTHORIZED);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, ErrorResponse errorResponse,
                               @Nonnull StatusReason reason)
    {
        handleFailure(context, new ErrorResponseException(errorResponse), Collections.emptyMap(), reason);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, int code, @Nonnull String meaning,
                               @Nonnull StatusReason reason)
    {
        handleFailure(context, new ErrorResponseException(code, meaning), Collections.emptyMap(), reason);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull ErrorResponseException errorResponse,
                               @Nonnull StatusReason reason)
    {
        handleFailure(context, errorResponse, Collections.emptyMap(), reason);
    }

    private void handleFailure(@Nonnull ChannelHandlerContext context, @Nonnull ErrorResponseException errorResponse,
                               @Nonnull Map<String, String> header, @Nonnull StatusReason reason)
    {
        try
        {
            BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, errorResponse.getObject().toBinary(), true);
            Response response = new Response(context, reason, new CaseInsensitiveMap<>(header), body);
            context.writeAndFlush(response);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
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
