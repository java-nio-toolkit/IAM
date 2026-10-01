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

package com.github.reganjohn.iam.test.restaction.applications.self;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.applications.self.PermissionOverrideEditActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.api.utils.data.BufferObject;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PermissionOverrideEditActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");

    private PermissionOverrideEditActionImpl newAction()
    {
        return new PermissionOverrideEditActionImpl(api);
    }

    private PermissionOverrideEditActionImpl newAction(ArgumentCaptor<DataObject> modified)
    {
        PermissionOverrideEditActionImpl action = spy(newAction());
        doReturn(completed(null)).when(action).modify(any(PermissionOverride.class), modified.capture());
        return action;
    }

    private PermissionOverride withStoredEntitlement()
    {
        PermissionOverride entitlement = withEntitlement(USER_ID, APPLICATION_ID, OWNER_ID, 1, 0);
        User user = withUser(USER_ID, "alice", null, 0);
        withEntitlement(user, APPLICATION_ID, completed(entitlement));
        withAccess(USER_ID);
        withRetrieval(USER_ID, completed(user));
        return entitlement;
    }

    @SuppressWarnings("unchecked")
    private InteractionMappingActionImpl<Void> modification(DataObject body)
    {
        withJCA();
        return (InteractionMappingActionImpl<Void>) newAction().modify(withEntitlement(USER_ID, APPLICATION_ID, OWNER_ID, 1, 0), body);
    }

    private static BufferArray rows(boolean empty, boolean applied)
    {
        BufferObject row = mock(BufferObject.class);
        BufferArray rows = mock(BufferArray.class);
        when(row.getBoolean("[applied]")).thenReturn(applied);
        when(rows.isEmpty()).thenReturn(empty);
        when(rows.getObject(0)).thenReturn(row);
        return rows;
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("empty_body", body()),
                arguments("permissions_not_number", body("permissions", "all")),
                arguments("permissions_null", "{\"permissions\":null}"),
                arguments("permissions_fraction", body("permissions", 1.5)));
    }

    static Stream<Arguments> testInvalidApplicationId()
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

    static Stream<Arguments> testModifyMissing()
    {
        return Stream.of(arguments(true, false), arguments(false, false));
    }

    @Test
    void testNonObject()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .withBody(nonObjectBody())
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .withBody(mock(RequestBody.class))
                .hasFailureMatchingSnapshot()
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest(name = "{0}")
    void testInvalidInputs(String name, String json)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(json)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidApplicationId(String name, String applicationId)
    {
        withAccess(USER_ID);

        assertThatRequestTo(newAction())
                .withRouteParams(applicationId)
                .withJsonBody(body("permissions", 1))
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @ValueSource(strings = {
            "{\"permissions\":0}",
            "{\"permissions\":1}",
            "{\"permissions\":9223372036854775807}",
            "{\"permissions\":1,\"unknown\":true}"})
    @ParameterizedTest
    void testValidInputs(String json)
    {
        withStoredEntitlement();
        ArgumentCaptor<DataObject> modified = ArgumentCaptor.forClass(DataObject.class);

        assertThatRequestTo(newAction(modified))
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(json)
                .hasStatus(StatusReason.NO_CONTENT.code)
                .hasNoBody()
                .whenHandled();

        assertThat(modified.getAllValues()).hasSize(1);
    }

    @Test
    void testValidEntitlement()
    {
        PermissionOverride entitlement = withStoredEntitlement();
        ArgumentCaptor<DataObject> modified = ArgumentCaptor.forClass(DataObject.class);
        PermissionOverrideEditActionImpl action = newAction(modified);

        assertThatRequestTo(action)
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("permissions", 0))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .whenHandled();

        verify(action).modify(entitlement, modified.getValue());
        assertThat(modified.getValue().getLong("permissions")).isZero();
    }

    @Test
    void testUnknownUser()
    {
        withAccess(USER_ID);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("permissions", 1))
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
                .withJsonBody(body("permissions", 1))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testModifyFailure()
    {
        withStoredEntitlement();
        PermissionOverrideEditActionImpl action = spy(newAction());
        doReturn(failed(new ErrorResponseException(ErrorResponse.UNKNOWN_ENTITLEMENT))).when(action).modify(any(PermissionOverride.class), any(DataObject.class));

        assertThatRequestTo(action)
                .withRouteParams(APPLICATION_ID.toString())
                .withJsonBody(body("permissions", 1))
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
                .withJsonBody(body("permissions", 1))
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
                .withJsonBody(body("permissions", 1))
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().modify(null, DataObject.empty()));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().modify(withEntitlement(USER_ID, APPLICATION_ID, OWNER_ID, 1, 0), null));
    }

    @Test
    void testModifyStatement()
    {
        InteractionMappingActionImpl<Void> modification = modification(DataObject.empty());

        assertThat(modification.getContent()).contains("UPDATE users.entitlements", "permissions = :permissions",
                "updated_at = :updated_at", "user_id = :user_id", "application_id = :application_id", "IF EXISTS");
        assertThatStatementIsBound(modification);
    }

    @Test
    void testModifyKeepsStoredPermissions()
    {
        assertThat(modification(DataObject.empty()).getParams())
                .containsEntry("user_id", USER_ID)
                .containsEntry("application_id", APPLICATION_ID)
                .containsEntry("permissions", 1L)
                .containsKey("updated_at");
    }

    @Test
    void testModifyOverridesStoredPermissions()
    {
        assertThat(modification(DataObject.empty().put("permissions", 0)).getParams())
                .containsEntry("permissions", 0L);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testModifyApplied() throws Exception
    {
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);

        modification(DataObject.empty()).handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows(false, true));

        verify(interaction).onSuccess(null);
    }

    @MethodSource
    @ParameterizedTest
    @SuppressWarnings("unchecked")
    void testModifyMissing(boolean empty, boolean applied) throws Exception
    {
        InteractionImpl<Void> interaction = mock(InteractionImpl.class);

        modification(DataObject.empty()).handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows(empty, applied));

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.UNKNOWN_ENTITLEMENT.getCode()));
    }
}
