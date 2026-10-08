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

package com.github.reganjohn.iam.test.restaction.user;

import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.UserRetrieveActionImpl;
import com.github.reganjohn.iam.test.assertions.restaction.RestActionAssertions;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.verify;

public class UserRetrieveActionTest extends RestActionTest
{
    protected static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");

    protected UserRetrieveActionImpl newAction()
    {
        return new UserRetrieveActionImpl(api);
    }

    protected RestActionAssertions assertThatRetrieving(String userId)
    {
        return assertThatRequestTo(newAction()).withRouteParams(userId);
    }

    protected String getUserIdField()
    {
        return "user_id";
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("empty", "", "BASE_TYPE_REQUIRED"),
                arguments("not_uuid", "not-a-uuid", "UUID_TYPE_COERCE"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96", "UUID_TYPE_COERCE"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", "UUID_TYPE_COERCE"),
                arguments("surrounded_by_spaces", " 01a0f15f-ef22-7d1e-9a96-432acf9b644f ", "UUID_TYPE_COERCE"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f", "UUID_TYPE_COERCE"));
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String userId, String code)
    {
        assertThatRetrieving(userId)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFormErrors(getUserIdField(), code)
                .hasNoResponse()
                .whenHandled();
    }

    @ValueSource(strings = {
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "01A0F15F-EF22-7D1E-9A96-432ACF9B644F",
            "01a0f15f-ef22-7d1e-9a96-432acf9b644f"})
    @ParameterizedTest
    void testValidInputs(String userId)
    {
        UUID id = UUID.fromString(userId);
        withRetrieval(completed(withUser(id, "alice", null, 0)));

        assertThatRetrieving(userId)
                .hasStatus(StatusReason.OK.code)
                .whenHandled();

        verify(api).retrieveUserById(id);
    }

    @Test
    void testValidUser()
    {
        withRetrieval(USER_ID, completed(withUser(USER_ID, "alice", "avatar-cid", 5)));

        assertThatRetrieving(USER_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasContentType(UserRetrieveActionImpl.MEDIA_TYPE_JSON)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMinimalUser()
    {
        withRetrieval(USER_ID, completed(withUser(USER_ID, "a", null, 0)));

        assertThatRetrieving(USER_ID.toString())
                .hasStatus(StatusReason.OK.code)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownUser()
    {
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRetrieving(USER_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_USER)
                .whenHandled();
    }
}
