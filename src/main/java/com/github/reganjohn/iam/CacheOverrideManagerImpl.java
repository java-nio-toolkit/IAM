/*
 * Copyright 2026 Ada Morgan, John Regan and the JNT contributors
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

package com.github.reganjohn.iam;

import com.github.adamorgan.jnt.api.interactions.cache.CacheContextBuilder;
import com.github.adamorgan.jnt.api.requests.Method;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.internal.managers.AbstractInteractionObjectManagerImpl;
import io.netty.channel.ChannelHandlerContext;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class CacheOverrideManagerImpl extends AbstractInteractionObjectManagerImpl
{
    @Override
    public void handleResponse(@Nonnull ChannelHandlerContext context, @Nonnull Request request, @Nonnull Response response)
    {
        Map<String, String> headers = finalizeHeaders();
        headers.forEach(response.getHeaders()::putIfAbsent);
    }

    @Nonnull
    @Unmodifiable
    private Map<String, String> finalizeHeaders()
    {
        return new CacheContextBuilder()
                .setAvailable(true)
                .setMaxAge(3600, TimeUnit.SECONDS)
                .toMap();
    }

    @Override
    public boolean filter(@Nullable Request request, @Nonnull Response response)
    {
        return filter(request.getRoute().getMethod());
    }

    private boolean filter(@Nonnull Method method)
    {
        return method == Method.GET || method == Method.HEAD;
    }

    @Override
    public boolean isSharable()
    {
        return true;
    }
}
