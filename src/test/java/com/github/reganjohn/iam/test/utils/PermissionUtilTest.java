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

package com.github.reganjohn.iam.test.utils;

import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.EnumSet;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;

public class PermissionUtilTest
{
    private static DataObject entry(Object type, Object actions)
    {
        return DataObject.empty().put("type", type).put("actions", actions);
    }

    private static DataArray actions(Object... values)
    {
        DataArray array = DataArray.empty();
        for (Object value : values)
            array.add(value);
        return array;
    }

    static Stream<Arguments> testInvalidAccess()
    {
        return Stream.of(
                arguments("string_entry", DataArray.empty().add("account.read")),
                arguments("number_entry", DataArray.empty().add(5)),
                arguments("null_entry", DataArray.empty().add(null)),
                arguments("nested_array", DataArray.empty().add(DataArray.empty())),
                arguments("type_missing", DataArray.empty().add(DataObject.empty().put("actions", actions("read")))),
                arguments("type_not_string", DataArray.empty().add(entry(5, actions("read")))),
                arguments("actions_missing", DataArray.empty().add(DataObject.empty().put("type", "account"))),
                arguments("actions_not_array", DataArray.empty().add(entry("account", "read"))),
                arguments("action_not_string", DataArray.empty().add(entry("account", actions(5)))),
                arguments("action_null", DataArray.empty().add(entry("account", actions((Object) null)))),
                arguments("unknown_type", DataArray.empty().add(entry("photo", actions("read")))),
                arguments("unknown_action", DataArray.empty().add(entry("account", actions("write")))),
                arguments("wrong_case", DataArray.empty().add(entry("Account", actions("Read")))),
                arguments("valid_then_invalid", DataArray.empty().add(entry("account", actions("read"))).add(entry("account", actions("write")))),
                arguments("unknown_permission", DataArray.empty().add(entry("unknown", actions("unknown")))));
    }

    @Test
    void testValidAccess()
    {
        assertThat(PermissionUtil.isValid(DataArray.empty())).isTrue();
        assertThat(PermissionUtil.isValid(DataArray.empty().add(entry("account", DataArray.empty())))).isTrue();
        assertThat(PermissionUtil.isValid(DataArray.empty().add(entry("account", actions("read", "read"))))).isTrue();
    }

    @Test
    void testRawOfEmptyArray()
    {
        assertThat(PermissionUtil.toRaw(DataArray.empty())).isZero();
    }

    @Test
    void testRawOfEmptyActions()
    {
        assertThat(PermissionUtil.toRaw(DataArray.empty().add(entry("account", DataArray.empty())))).isZero();
    }

    @Test
    void testRawOfAccess()
    {
        assertThat(PermissionUtil.toRaw(DataArray.empty().add(entry("account", actions("read")))))
                .isEqualTo(Permission.VIEW_ACCOUNT.getRawValue());
    }

    @Test
    void testRawIgnoresRepeatsAndExtraMembers()
    {
        DataObject read = entry("account", actions("read", "read")).put("locations", actions("https://example.org"));

        assertThat(PermissionUtil.toRaw(DataArray.empty().add(read).add(read)))
                .isEqualTo(Permission.VIEW_ACCOUNT.getRawValue());
    }

    @Test
    void testRoundTrip()
    {
        for (Permission permission : Permission.values())
        {
            if (permission == Permission.UNKNOWN)
                continue;
            EnumSet<Permission> set = EnumSet.of(permission);

            assertThat(PermissionUtil.toRaw(PermissionUtil.toDataArray(set))).isEqualTo(Permission.getRaw(set));
        }
    }

    @MethodSource
    @ParameterizedTest(name = "{0}")
    void testInvalidAccess(String name, DataArray access)
    {
        assertThat(PermissionUtil.isValid(access)).isFalse();
        assertThatIllegalArgumentException().isThrownBy(() -> PermissionUtil.toRaw(access));
    }
}
