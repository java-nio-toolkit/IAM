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
import com.github.reganjohn.iam.internal.requests.restactions.entitlements.PermissionOverrideDeleteActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PermissionOverrideDeleteActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");

    private PermissionOverrideDeleteActionImpl newAction()
    {
        return new PermissionOverrideDeleteActionImpl(api);
    }

    private User withStoredEntitlement(UUID applicationId, PermissionOverride entitlement)
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withEntitlement(user, applicationId, completed(entitlement));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
        return user;
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "04d3c48c-1255-7041-8dc9"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
                arguments("without_dashes", "04d3c48c125570418dc9765df2ce977c"));
    }

    static Stream<Arguments> testInvalidSubject()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "01a0f15f-ef22-7d1e-9a96"),
                arguments("without_dashes", "01a0f15fef227d1e9a96432acf9b644f"));
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidInputs(String name, String applicationId)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(applicationId)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @ValueSource(strings = {
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "04D3C48C-1255-7041-8DC9-765DF2CE977C",
            "04d3c48c-1255-7041-8dc9-765df2ce977c"})
    @ParameterizedTest
    void testValidInputs(String applicationId)
    {
        UUID id = UUID.fromString(applicationId);
        User user = withStoredEntitlement(id, withEntitlement(USER_ID, id, OWNER_ID, 0, 0));

        assertThatRequestTo(newAction())
                .withRouteParams(applicationId)
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        verify(user).retrieveEntitlementById(id);
    }

    @Test
    void testValidEntitlement()
    {
        PermissionOverride entitlement = withEntitlement(USER_ID, APPLICATION_ID, OWNER_ID, 1, 0);
        InteractionCallbackAction<Void> deletion = completed(null);
        when(entitlement.delete()).thenReturn(deletion);
        withStoredEntitlement(APPLICATION_ID, entitlement);

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasStatus(StatusReason.NO_CONTENT.code)
                .hasNoBody()
                .whenHandled();

        verify(entitlement).delete();
        verify(deletion).queue(any(), any());
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownEntitlement()
    {
        User user = withUser(USER_ID, "alice", null, 0);
        withEntitlement(user, APPLICATION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_ENTITLEMENT)));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testDeleteFailure()
    {
        PermissionOverride entitlement = withEntitlement(USER_ID, APPLICATION_ID, OWNER_ID, 1, 0);
        InteractionCallbackAction<Void> deletion = failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS));
        when(entitlement.delete()).thenReturn(deletion);
        withStoredEntitlement(APPLICATION_ID, entitlement);

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testMissingAccess()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidSubject(String name, String subject)
    {
        withAccess(subject);

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }
}
