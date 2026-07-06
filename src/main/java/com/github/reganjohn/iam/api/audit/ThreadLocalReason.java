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

package com.github.reganjohn.iam.api.audit;

import io.netty.channel.ChannelHandlerContext;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class ThreadLocalReason
{
    public static final AttributeKey<String> REASON = AttributeKey.valueOf("currentReason");

    private ThreadLocalReason()
    {
        throw new UnsupportedOperationException();
    }

    public static void setCurrent(@Nonnull ChannelHandlerContext context, @Nullable String reason)
    {
        Attribute<String> currentReason = context.channel().attr(REASON);
        if (reason != null)
        {
            currentReason.set(reason);
        }
        else
        {
            if (currentReason.get() != null)
            {
                currentReason.set(null);
            }
        }
    }

    /**
     * Resets the currently set thread-local reason, if present.
     */
    public static void resetCurrent(@Nonnull ChannelHandlerContext context)
    {
        context.channel().attr(REASON).set(null);
    }

    @Nullable
    public static String getCurrent(@Nonnull ChannelHandlerContext context)
    {
        return context.channel().attr(REASON).get();
    }

    /**
     * Creates a new {@link Closable} instance.
     * <br>Allows to use try-with-resources blocks for setting reasons
     *
     * @return The closable instance
     */
    @Nonnull
    public static Closable closable(@Nonnull ChannelHandlerContext context)
    {
        return new Closable(context);
    }

    /**
     * Allows to use try-with-resources blocks for setting reasons
     */
    public static class Closable implements AutoCloseable
    {
        private final ChannelHandlerContext context;
        private final String previous;

        public Closable(@Nonnull ChannelHandlerContext context)
        {
            this.context = context;
            this.previous = getCurrent(context);
        }

        @Override
        public void close()
        {
            setCurrent(context, previous);
        }
    }
}
