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

package com.github.reganjohn.iam.internal.requests.restactions.application;

import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.reganjohn.iam.internal.IAMImpl;

import javax.annotation.Nonnull;

public abstract class AbstractApplicationActionImpl extends RestActionImpl
{
    protected final IAMImpl api;

    public AbstractApplicationActionImpl(IAMImpl api, @Nonnull Route route)
    {
        super(route);
        this.api = api;
    }
}
