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

package com.github.reganjohn.iam.internal.requests.restactions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.restactions.AbstractOverrideAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.StringJoiner;
import java.util.UUID;

import static com.github.adamorgan.jnt.api.managers.ProofObjectManager.INVALID_REQUEST;

public abstract class AbstractOverrideActionImpl extends RestActionImpl implements AbstractOverrideAction
{
    protected final IAMImpl api;

    public AbstractOverrideActionImpl(@Nonnull IAMImpl api, @Nonnull Route route)
    {
        super(route);
        this.api = api;
    }

    @Nonnull
    @Override
    public IAMImpl getIAM()
    {
        return api;
    }

    protected void handleErrorResponse(@Nonnull String name, @Nonnull DataObjectParsingException exception,
                                       @Nonnull List<InvalidResponseException.SchemaError> errors)
    {
        InvalidResponseException.ErrorCode errorCode = new InvalidResponseException.ErrorCode(exception.getErrorCode(), exception.getMeaning());
        InvalidResponseException.SchemaError schemaError = new InvalidResponseException.SchemaError(name, Collections.singletonList(errorCode));
        errors.add(schemaError);
    }

    @Nonnull
    protected ErrorResponseException createErrorResponse(@Nonnull String name, @Nonnull DataObjectParsingException exception)
    {
        List<InvalidResponseException.SchemaError> errors = new ArrayList<>();
        handleErrorResponse(name, exception, errors);
        return new ErrorResponseException(ErrorResponse.INVALID_FORM_BODY, errors);
    }

    @Nonnull
    protected DataObjectParsingException createParsingException(@Nonnull Collection<String> set)
    {
        StringJoiner joiner = new StringJoiner(", ");
        for (String type : set)
            joiner.add("'" + type + "'");
        return new DataObjectParsingException(BASE_TYPE_CHOICES,
                Helpers.format("Value must be one of (%s).", joiner));
    }
    @Nonnull
    protected AccessObjectData retrieveSelfAccess(@Nonnull ChannelHandlerContext context)
    {
        AccessObjectData data = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        if (data == null)
            throw new ErrorResponseException(ErrorResponse.MISSING_ACCESS);
        else
            return data;
    }

    @Nonnull
    protected UUID retrieveSelfUserId(@Nonnull ChannelHandlerContext context)
    {
        AccessObjectData data = retrieveSelfAccess(context);
        if (!MiscUtil.isUUID(data.getSubject()))
            throw new ErrorResponseException(ErrorResponse.INVALID_TOKEN);
        else
            return UUID.fromString(data.getSubject());
    }

    @Nonnull
    protected ProofObjectData retrieveSelfProof(@Nonnull ChannelHandlerContext context)
    {
        ProofObjectData data = context.channel().attr(ProofObjectManagerImpl.CONTEXT).get();
        if (data == null)
            throw new ProofAccessException(api.getIdentifierString(), INVALID_REQUEST, "This action requires a DPoP proof.");
        else
            return data;
    }
}
