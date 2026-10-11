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

import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofCryptoManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.IAMImpl;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.UUID;

public class SessionCryptoManagerImpl extends ProofCryptoManagerImpl
{
    private final IAMImpl api;

    public SessionCryptoManagerImpl(@Nonnull IAMImpl api)
    {
        this.api = api;
    }

    @Override
    public void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        AccessObjectData data = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        if (data == null || !MiscUtil.isUUID(data.getSubject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        api.retrieveUserById(UUID.fromString(data.getSubject()))
                .flatMap(User::retrieveSessions)
                .queue(sessions -> handleSuccess(context, request, data, sessions), context::fireExceptionCaught);
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                               @Nonnull AccessObjectData data, @Nonnull List<Session> sessions)
    {
        if (sessions.stream().anyMatch(session -> Helpers.equals(session.getThumbprint(), data.getThumbprint(), false)))
            super.handleSuccess(context, request);
        else
            context.fireExceptionCaught(new ErrorResponseException(ErrorResponse.INVALID_TOKEN));
    }
}
