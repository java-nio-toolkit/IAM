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

package com.github.reganjohn.iam.test.exceptions;

import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ErrorResponseTest
{
    @Test
    void testErrorResponse()
    {
        assertThat(ErrorResponse.UNKNOWN_SESSION.test(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION))).isTrue();
        assertThat(ErrorResponse.UNKNOWN_SESSION.test(new ErrorResponseException(ErrorResponse.UNKNOWN_USER))).isFalse();
        assertThat(ErrorResponse.UNKNOWN_SESSION.test(new IllegalStateException())).isFalse();
        assertThat(ErrorResponse.UNKNOWN_SESSION.test(null)).isFalse();
    }
}
