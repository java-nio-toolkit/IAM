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

import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.managers.GlobalRestRateLimiter;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.lang3.exception.UncheckedException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.concurrent.TimeUnit;

public class SubjectRestRateLimiter extends GlobalRestRateLimiter
{
    public SubjectRestRateLimiter(int limit, int globalRateLimit, int timeout, @Nonnull TimeUnit unit, @Nonnull String scope)
    {
        this(limit, globalRateLimit, timeout, unit, scope, 0);
    }

    public SubjectRestRateLimiter(int limit, int globalRateLimit, int timeout, @Nonnull TimeUnit unit, @Nonnull String scope, int maxQueueSize)
    {
        super(limit, globalRateLimit, timeout, unit, scope, maxQueueSize);
    }

    @Nullable
    @Override
    protected String getSubject(@Nullable ChannelHandlerContext context)
    {
        String subject = super.getSubject(context);
        String thumbprint = getThumbprint(context);
        if (thumbprint == null)
            return subject;
        return subject != null ? subject + ":" + thumbprint : thumbprint;
    }

    @Nullable
    private String getThumbprint(ChannelHandlerContext context)
    {
        return context != null ? Helpers.get(context, ProofObjectManagerImpl.CONTEXT, this::getThumbprint) : null;
    }

    @Nonnull
    private String getThumbprint(@Nonnull ProofObjectData data)
    {
        try (AccessContextData contextData = data.getContext(AccessContextType.SHA_256))
        {
            return contextData.digest();
        }
        catch (Exception ex)
        {
            throw new UncheckedException(ex);
        }
    }
}
