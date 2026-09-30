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

import com.fasterxml.jackson.databind.JsonNode;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.exceptions.DataObjectParsingException;
import com.github.reganjohn.iam.api.requests.restactions.ApplicationAction;
import com.github.reganjohn.iam.internal.IAMImpl;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.StreamSupport;

public abstract class AbstractApplicationActionImpl extends AbstractOverrideActionImpl implements ApplicationAction
{
    public AbstractApplicationActionImpl(@Nonnull IAMImpl api, @Nonnull Route route)
    {
        super(api, route);
    }


    protected void checkOwnerId(@Nonnull Map<String, String> params)
    {
        String id = params.get("user_id");
        if (Helpers.isEmpty(id))
            throw new DataObjectParsingException(BASE_TYPE_REQUIRED, "This field is required");
        else if (!MiscUtil.isUUID(id))
            throw new DataObjectParsingException(UUID_TYPE_COERCE, "The \"user_id\" value is not uuid.");
    }

    protected void checkRedirectUris(@Nonnull DataArray array)
    {
        if (array.isEmpty())
            throw new DataObjectParsingException(BASE_TYPE_MIN_LENGTH, "The \"redirect_uris\" value may not be empty.");
        else if (array.size() > Application.MAX_URL_COUNT)
            throw new DataObjectParsingException(BASE_TYPE_MAX_LENGTH,
                    Helpers.format("Must be %s or fewer in length.", Application.MAX_URL_COUNT));
        else if (!array.allMatch(JsonNode::isTextual))
            throw new DataObjectParsingException(STRING_TYPE_COERCE, "The \"redirect_uris\" contains value which is not a string.");
        else if (!array.allMatch(node -> node.textValue().length() <= Application.MAX_URL_LENGTH))
            throw new DataObjectParsingException(STRING_TYPE_MAX,
                    Helpers.format("The \"redirect_uris\" value may not be longer than %d characters.", Application.MAX_URL_LENGTH));
        else if (!array.allMatch(node -> MiscUtil.isURL(node.textValue(), false)))
            throw new DataObjectParsingException(BASE_TYPE_CHOICES, "The \"redirect_uris\" contains value which is not a url.");
    }
}
