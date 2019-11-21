/*
 * Copyright 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

/**
 * CallOrderStateMachineHelper is a helper class for setting up a compile-time
 * checked state machine that a sequence of calls is correct for completely
 * setting up the state for some other type.
 *
 * Two examples where this could be used are with setting up a "Builder" flow
 * for initializing an instance of some type, and writing tests where the state
 * machine sets up expectations and preconditions, calls the function under
 * test, and then evaluations postconditions.
 *
 * The purpose of this helper is to offload some of the boilerplate code to
 * simplify the actual state classes, and is also a place to document how to
 * go about setting up the state classes.
 *
 * To work at compile time, the idea is that each state is a unique C++ type,
 * and the valid transitions between states are given by member functions on
 * those types, with those functions returning a simple value type expressing
 * the new state to use. Illegal state transitions become a compile error because
 * a named member function does not exist.
 *
 * Example usage in a test:
 *
 *    A two step (+ terminator step) setup process can defined using:
 *
 *        class Step1 : public CallOrderStateMachineHelper<TestFixtureType, Step1> {
 *           [[nodiscard]] auto firstMockCalledWith(int value1) {
 *              // Set up an expectation or initial state using the fixture
 *              EXPECT_CALL(getInstance->firstMock, FirstCall(value1));
 *              return nextState<Step2>();
 *           }
 *        };
 *
 *        class Step2 : public CallOrderStateMachineHelper<TestFixtureType, Step2> {
 *           [[nodiscard]] auto secondMockCalledWith(int value2) {
 *              // Set up an expectation or initial state using the fixture
 *              EXPECT_CALL(getInstance()->secondMock, SecondCall(value2));
 *              return nextState<StepExecute>();
 *           }
 *        };
 *
 *        class StepExecute : public CallOrderStateMachineHelper<TestFixtureType, Step3> {
 *           void execute() {
 *              invokeFunctionUnderTest();
 *           }
 *        };
 *
 *    Note how the non-terminator steps return by value and use [[nodiscard]] to
 *    enforce the setup flow. Only the terminator step returns void.
 *
 *    This can then be used in the tests with:
 *
 *        Step1::make(this).firstMockCalledWith(value1)
 *                .secondMockCalledWith(value2)
 *                .execute);
 *
 *    If the test fixture defines a `verify()` helper function which returns
 *    `Step1::make(this)`, this can be simplified to:
 *
 *        verify().firstMockCalledWith(value1)
 *                .secondMockCalledWith(value2)
 *                .execute();
 *
 *    This is equivalent to the following calls made by the text function:
 *
 *        EXPECT_CALL(firstMock, FirstCall(value1));
 *        EXPECT_CALL(secondMock, SecondCall(value2));
 *        invokeFunctionUnderTest();
 */
template <typename InstanceType, typename CurrentStateType>
class CallOrderStateMachineHelper {
public:
    CallOrderStateMachineHelper() = default;

    // Disallow copying
    CallOrderStateMachineHelper(const CallOrderStateMachineHelper&) = delete;
    CallOrderStateMachineHelper& operator=(const CallOrderStateMachineHelper&) = delete;

    // Moving is intended use case.
    CallOrderStateMachineHelper(CallOrderStateMachineHelper&&) = default;
    CallOrderStateMachineHelper& operator=(CallOrderStateMachineHelper&&) = default;

    // Using a static "Make" function means the CurrentStateType classes do not
    // need anything other than a default no-argument constructor.
    static CurrentStateType make(InstanceType* instance) {
        auto helper = CurrentStateType();
        helper.mInstance = instance;
        return helper;
    }

    // Each non-terminal state function
    template <typename NextStateType>
    auto nextState() {
        // Note: Further operations on the current state become undefined
        // operations as the instance pointer is moved to the next state type.
        // But that doesn't stop someone from storing an intermediate state
        // instance as a local and possibly calling one than one member function
        // on it. By swapping with nullptr, we at least can try to catch this
        // this at runtime.
        InstanceType* instance = nullptr;
        std::swap(instance, mInstance);
        return NextStateType::make(instance);
    }

    InstanceType* getInstance() const { return mInstance; }

private:
    InstanceType* mInstance;
};
