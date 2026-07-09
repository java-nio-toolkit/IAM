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

package com.github.reganjohn.iam.internal.requests.restactions.self;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.audit.ThreadLocalReason;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.self.SelfUserRetrieveAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.UserRetrieveActionImpl;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.Nonnull;
import java.util.List;

public class SelfUserRetrieveActionImpl extends UserRetrieveActionImpl implements SelfUserRetrieveAction
{
    public SelfUserRetrieveActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Self.GET_SELF);
    }

    @Override
    protected void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                 @Nonnull List<InvalidResponseException.SchemaError> schemaErrors)
    {
        AccessObjectData data = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        try (ThreadLocalReason.Closable closable = ThreadLocalReason.closable(context))
        {
            checkUserId(data.getSubject());
        }
        catch (DataObjectParsingException ex)
        {
            handleErrorResponse("sub", ex, schemaErrors);
        }
        finally
        {
            handleInternally(context, data.getSubject(), schemaErrors);
        }
    }

    @Override
    public void checkUserId(@Nonnull String id)
    {
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"sub\" value is not uuid.");
    }
}
