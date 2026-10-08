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

package com.github.reganjohn.iam.test.restaction.entitlements;

import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.entitlements.PermissionOverridePaginationActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class PermissionOverridePaginationActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID FIRST_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final UUID SECOND_ID = UUID.fromString("05e4d59d-2366-7152-9eda-876e03dfa88d");

    private PermissionOverridePaginationActionImpl newAction()
    {
        return new PermissionOverridePaginationActionImpl(api);
    }

    private void withStoredEntitlements(PermissionOverride... entitlements)
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withEntitlements(user, completed(Arrays.asList(entitlements)));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
    }

    static Stream<Arguments> testInvalidSubject()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f"));
    }

    @Test
    void testValidEntitlements()
    {
        withStoredEntitlements(
                withEntitlement(USER_ID, FIRST_ID, OWNER_ID, 1, 0),
                withEntitlement(USER_ID, SECOND_ID, OWNER_ID, 0, 0));

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.OK.code)
                .hasContentType(PermissionOverridePaginationActionImpl.MEDIA_TYPE_JSON)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testSingleEntitlement()
    {
        withStoredEntitlements(withEntitlement(USER_ID, FIRST_ID, OWNER_ID, 1, 0));

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.OK.code)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testEmpty()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withEntitlements(user, completed(Collections.emptyList()));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .hasStatus(StatusReason.OK.code)
                .hasBodyMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.UNKNOWN_USER)
                .whenHandled();
    }

    @Test
    void testRetrievalFailure()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withEntitlements(user, failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS)));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.MISSING_ACCESS)
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.MISSING_ACCESS)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidSubject(String name, String subject)
    {
        withAccess(subject);

        assertThatRequestTo(newAction())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailure(ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }
}
