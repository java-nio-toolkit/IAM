/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.reganjohn.iam.test;

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.data.SerializableData;
import com.github.reganjohn.iam.test.util.SnapshotHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;

public class AbstractSnapshotTest
{
    protected SnapshotHandler snapshotHandler;

    @BeforeEach
    void initializeSnapshotHandler(TestInfo info)
    {
        this.snapshotHandler = new SnapshotHandler(info);
    }

    protected void assertWithSnapshot(String actual, String suffix)
    {
        snapshotHandler.compareWithSnapshot(actual, suffix);
    }

    protected void assertWithSnapshot(DataObject data, String suffix)
    {
        snapshotHandler.compareWithSnapshot(data, suffix);
    }

    protected void assertWithSnapshot(SerializableData data)
    {
        snapshotHandler.compareWithSnapshot(data.toData(), null);
    }
}
