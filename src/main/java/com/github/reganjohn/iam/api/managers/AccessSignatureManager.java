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

package com.github.reganjohn.iam.api.managers;

import com.github.adamorgan.jnt.api.managers.ProofSignatureManager;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import io.netty.channel.ChannelHandlerContext;

import javax.annotation.Nonnull;

public interface AccessSignatureManager extends ProofSignatureManager
{
    @Nonnull
    AccessEntryData verify(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                           @Nonnull DataObject raw);

    void verify(@Nonnull ChannelHandlerContext context, @Nonnull Request request, @Nonnull AccessEntryData data);
}
