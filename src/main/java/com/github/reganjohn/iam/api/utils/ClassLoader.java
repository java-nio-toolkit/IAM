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

package com.github.reganjohn.iam.api.utils;

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import org.jetbrains.annotations.Contract;

import javax.annotation.Nonnull;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

public class ClassLoader
{
    @Nonnull
    public static String getResourceAsString(@Nonnull String name)
    {
        Checks.notEmpty(name, "Name");
        java.lang.ClassLoader loader = Thread.currentThread().getContextClassLoader();
        try (InputStream in = loader.getResourceAsStream(name))
        {
            if (in == null)
                throw new FileNotFoundException(Helpers.format("The file %s does not exist.", name));
            else
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException error)
        {
            throw new UncheckedIOException(error);
        }
    }
}
