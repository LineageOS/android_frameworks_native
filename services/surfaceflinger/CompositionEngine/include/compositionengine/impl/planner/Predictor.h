/*
 * Copyright 2021 The Android Open Source Project
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

#include <compositionengine/impl/planner/LayerState.h>

namespace android::compositionengine::impl::planner {

class LayerStack {
public:
    LayerStack(const std::vector<const LayerState*>& layers) : mLayers(copyLayers(layers)) {}

    struct ApproximateMatch {
        bool operator==(const ApproximateMatch& other) const {
            return differingIndex == other.differingIndex &&
                    differingFields == other.differingFields;
        }

        size_t differingIndex;
        Flags<LayerStateField> differingFields;
    };

    std::optional<ApproximateMatch> getApproximateMatch(
            const std::vector<const LayerState*>& other) const;

    void compare(const LayerStack& other, std::string& result) const {
        if (mLayers.size() != other.mLayers.size()) {
            base::StringAppendF(&result, "Cannot compare stacks of different sizes (%zd vs. %zd)\n",
                                mLayers.size(), other.mLayers.size());
            return;
        }

        for (size_t l = 0; l < mLayers.size(); ++l) {
            const auto& thisLayer = mLayers[l];
            const auto& otherLayer = other.mLayers[l];
            base::StringAppendF(&result, "\n+ - - - - - - - - - Layer %d [%s]\n", thisLayer.getId(),
                                thisLayer.getName().c_str());
            auto comparisonOpt = thisLayer.compare(otherLayer);
            base::StringAppendF(&result,
                                "    %s     + - - - - - - - - - - - - - - - - - - - - - - - "
                                "- Layer %d [%s]\n",
                                comparisonOpt ? "         " : "Identical", otherLayer.getId(),
                                otherLayer.getName().c_str());
            if (comparisonOpt) {
                result.append(*comparisonOpt);
            }
        }
    }

    void dump(std::string& result) const {
        for (const LayerState& layer : mLayers) {
            base::StringAppendF(&result, "+ - - - - - - - - - Layer %d [%s]\n", layer.getId(),
                                layer.getName().c_str());
            layer.dump(result);
        }
    }

    void dumpLayerNames(std::string& result, const std::string& prefix = "  ") const {
        for (const LayerState& layer : mLayers) {
            result.append(prefix);
            result.append(layer.getName());
            result.append("\n");
        }
    }

private:
    std::vector<const LayerState> copyLayers(const std::vector<const LayerState*>& layers) {
        std::vector<const LayerState> copiedLayers;
        copiedLayers.reserve(layers.size());
        std::transform(layers.cbegin(), layers.cend(), std::back_inserter(copiedLayers),
                       [](const LayerState* layerState) { return *layerState; });
        return copiedLayers;
    }

    std::vector<const LayerState> mLayers;

    // TODO(b/180976743): Tune kMaxDifferingFields
    constexpr static int kMaxDifferingFields = 6;
};

class Plan {
public:
    static std::optional<Plan> fromString(const std::string&);

    void reset() { mLayerTypes.clear(); }
    void addLayerType(hardware::graphics::composer::hal::Composition type) {
        mLayerTypes.emplace_back(type);
    }

    friend std::string to_string(const Plan& plan);

    friend bool operator==(const Plan& lhs, const Plan& rhs) {
        return lhs.mLayerTypes == rhs.mLayerTypes;
    }
    friend bool operator!=(const Plan& lhs, const Plan& rhs) { return !(lhs == rhs); }

private:
    std::vector<hardware::graphics::composer::hal::Composition> mLayerTypes;
};

} // namespace android::compositionengine::impl::planner

namespace std {
template <>
struct hash<android::compositionengine::impl::planner::Plan> {
    size_t operator()(const android::compositionengine::impl::planner::Plan& plan) const {
        return std::hash<std::string>{}(to_string(plan));
    }
};
} // namespace std

namespace android::compositionengine::impl::planner {

class Prediction {
public:
    enum class Type {
        Exact,
        Approximate,
        Total,
    };

    friend std::string to_string(Type type) {
        using namespace std::string_literals;

        switch (type) {
            case Type::Exact:
                return "Exact";
            case Type::Approximate:
                return "Approximate";
            case Type::Total:
                return "Total";
        }
    }

    Prediction(const std::vector<const LayerState*>& layers, Plan plan)
          : mExampleLayerStack(layers), mPlan(std::move(plan)) {}

    const LayerStack& getExampleLayerStack() const { return mExampleLayerStack; }
    const Plan& getPlan() const { return mPlan; }

    size_t getHitCount(Type type) const {
        if (type == Type::Total) {
            return getHitCount(Type::Exact) + getHitCount(Type::Approximate);
        }
        return getStatsForType(type).hitCount;
    }

    size_t getMissCount(Type type) const {
        if (type == Type::Total) {
            return getMissCount(Type::Exact) + getMissCount(Type::Approximate);
        }
        return getStatsForType(type).missCount;
    }

    void recordHit(Type type) { ++getStatsForType(type).hitCount; }

    void recordMiss(Type type) { ++getStatsForType(type).missCount; }

    void dump(std::string&) const;

private:
    struct Stats {
        void dump(std::string& result) const {
            const size_t totalAttempts = hitCount + missCount;
            base::StringAppendF(&result, "%.2f%% (%zd/%zd)", 100.0f * hitCount / totalAttempts,
                                hitCount, totalAttempts);
        }

        size_t hitCount = 0;
        size_t missCount = 0;
    };

    const Stats& getStatsForType(Type type) const {
        return (type == Type::Exact) ? mExactStats : mApproximateStats;
    }

    Stats& getStatsForType(Type type) {
        return const_cast<Stats&>(const_cast<const Prediction*>(this)->getStatsForType(type));
    }

    LayerStack mExampleLayerStack;
    Plan mPlan;

    Stats mExactStats;
    Stats mApproximateStats;
};

class Predictor {
public:
    struct PredictedPlan {
        NonBufferHash hash;
        Plan plan;
        Prediction::Type type;
    };

    std::optional<PredictedPlan> getPredictedPlan(const std::vector<const LayerState*>&,
                                                  NonBufferHash) const;

    void recordResult(std::optional<PredictedPlan> predictedPlan,
                      const std::vector<const LayerState*>&, Plan result);

    void dump(std::string&) const;

    void compareLayerStacks(NonBufferHash leftHash, NonBufferHash rightHash, std::string&) const;
    void describeLayerStack(NonBufferHash, std::string&) const;
    void listSimilarStacks(Plan, std::string&) const;

private:
    // Retrieves a prediction from either the main prediction list or from the candidate list
    const Prediction& getPrediction(NonBufferHash) const;
    Prediction& getPrediction(NonBufferHash);

    std::optional<Plan> getExactMatch(NonBufferHash) const;
    std::optional<NonBufferHash> getApproximateMatch(
            const std::vector<const LayerState*>& layers) const;

    void promoteIfCandidate(NonBufferHash);
    void recordPredictedResult(PredictedPlan, const std::vector<const LayerState*>& layers,
                               Plan result);
    bool findSimilarPrediction(const std::vector<const LayerState*>& layers, Plan result);

    void dumpPredictionsByFrequency(std::string&) const;

    struct PromotionCandidate {
        PromotionCandidate(NonBufferHash hash, Prediction&& prediction)
              : hash(hash), prediction(std::move(prediction)) {}

        NonBufferHash hash;
        Prediction prediction;
    };

    static constexpr const size_t MAX_CANDIDATES = 4;
    std::deque<PromotionCandidate> mCandidates;
    decltype(mCandidates)::const_iterator getCandidateEntryByHash(NonBufferHash hash) const {
        const auto candidateMatches = [&](const PromotionCandidate& candidate) {
            return candidate.hash == hash;
        };

        return std::find_if(mCandidates.cbegin(), mCandidates.cend(), candidateMatches);
    }

    std::unordered_map<NonBufferHash, Prediction> mPredictions;
    std::unordered_map<Plan, std::vector<NonBufferHash>> mSimilarStacks;

    struct ApproximateStack {
        ApproximateStack(NonBufferHash hash, LayerStack::ApproximateMatch match)
              : hash(hash), match(match) {}

        bool operator==(const ApproximateStack& other) const {
            return hash == other.hash && match == other.match;
        }

        NonBufferHash hash;
        LayerStack::ApproximateMatch match;
    };

    std::vector<ApproximateStack> mApproximateStacks;

    mutable size_t mExactHitCount = 0;
    mutable size_t mApproximateHitCount = 0;
    mutable size_t mMissCount = 0;
};

} // namespace android::compositionengine::impl::planner
