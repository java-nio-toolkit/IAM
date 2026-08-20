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

package com.github.reganjohn.iam.api.requests.restactions;

import com.github.adamorgan.jnt.api.requests.restaction.RestAction;
import com.github.reganjohn.iam.internal.IAMImpl;

import javax.annotation.Nonnull;

public interface AbstractOverrideAction extends RestAction
{
    String UUID_TYPE_COERCE = "UUID_TYPE_COERCE";

    String STRING_TYPE_COERCE = "STRING_TYPE_COERCE";
    String STRING_TYPE_MIN = "STRING_TYPE_MIN";
    String STRING_TYPE_MAX = "STRING_TYPE_MAX";

    String NUMBER_TYPE_COERCE = "NUMBER_TYPE_COERCE";
    String NUMBER_TYPE_MIN = "NUMBER_TYPE_MIN";
    String NUMBER_TYPE_MAX = "NUMBER_TYPE_MAX";

    String LIST_ITEM_VALUE_REQUIRED = "LIST_ITEM_VALUE_REQUIRED";

    String DICT_TYPE_CONVERT = "DICT_TYPE_CONVERT";
    String MODEL_TYPE_CONVERT = "MODEL_TYPE_CONVERT";

    String BASE_TYPE_REQUIRED = "BASE_TYPE_REQUIRED";
    String BASE_TYPE_CHOICES = "BASE_TYPE_CHOICES";
    String BASE_TYPE_MIN_LENGTH = "BASE_TYPE_MIN_LENGTH";
    String BASE_TYPE_MAX_LENGTH = "BASE_TYPE_MAX_LENGTH";
    String BASE_TYPE_BAD_LENGTH = "BASE_TYPE_BAD_LENGTH";

    @Nonnull
    IAMImpl getIAM();
}
