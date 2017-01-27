#include "include/private/dvr/display_metrics.h"
#include <private/dvr/head_mount_metrics.h>
#include <private/dvr/identity_distortion.h>
#include <private/dvr/lookup_radial_distortion.h>
#include <private/dvr/lucid_metrics.h>
#include <private/dvr/types.h>

namespace {

// These numbers are specific to the OnePlus One and therefore
// temporary until we advance to the next Lucid development platform.

// Head mount metrics for Lucid A00
static const float kDefaultInterLensDistance = 0.064f;  // 64mm
static const float kDefaultTrayToLensDistance = 0.035f;
static const float kDefaultVirtualEyeToScreenDistance = 0.042f;
static const android::dvr::HeadMountMetrics::VerticalAlignment
    kDefaultVerticalAlignment = android::dvr::HeadMountMetrics::kCenter;
static const float kDefaultFovHalfAngleInsideH = 43.7f * M_PI / 180.0f;
static const float kDefaultFovHalfAngleOutsideH = 47.8f * M_PI / 180.0f;
static const float kDefaultFovHalfAngleV = 54.2f * M_PI / 180.0f;

// Screen size in meters for Lucid (Nexus 6 display in portrait mode).
static const android::dvr::vec2 kScreenSizeInMeters(0.0742177f, 0.131943f);

// Border size in meters for the OnePlus One.
static const float kScreenBorderSize = 0.004f;

// Refresh rate.
static const float kScreenRefreshRate = 60.0f;

// Lucid display orientation is portrait.
static const android::dvr::DisplayOrientation kDisplayOrientation =
    android::dvr::DisplayOrientation::kPortrait;

}  // anonymous namespace

namespace android {
namespace dvr {

// The distortion lookup tables were generated via a raytraced lens simulation.
// Please see for full calculations:
// https://docs.google.com/a/google.com/spreadsheets/d/
//       15cfHmCw5mHVOQ1rAJxMhta4q0e8zzcUDka1nRkfl7pY/edit?usp=sharing
LookupRadialDistortion* GetBlueDistortionLookup() {
  // clang-format off
  vec2 kBlueDistortionLookup[] = {
    {0.00000000000f, 1.00000000000f},
    {0.01888626190f, 1.00096958278f},
    {0.03777223810f, 1.00133301793f},
    {0.05665761905f, 1.00193985168f},
    {0.07554214286f, 1.00279048731f},
    {0.09442542857f, 1.00388751781f},
    {0.11330704762f, 1.00523363045f},
    {0.13218657143f, 1.00683149424f},
    {0.15106340476f, 1.00868516849f},
    {0.16993695238f, 1.01079861126f},
    {0.18880640476f, 1.01317712726f},
    {0.20767092857f, 1.01582607321f},
    {0.22652945238f, 1.01875203063f},
    {0.24538078571f, 1.02196207850f},
    {0.26422352381f, 1.02546421601f},
    {0.28305602381f, 1.02926737969f},
    {0.30187640476f, 1.03338139216f},
    {0.32068252381f, 1.03781702504f},
    {0.33947190476f, 1.04258620905f},
    {0.35824171429f, 1.04770206653f},
    {0.37698869048f, 1.05317909331f},
    {0.39570916667f, 1.05903306635f},
    {0.41439900000f, 1.06528124790f},
    {0.43305350000f, 1.07194257391f},
    {0.45166738095f, 1.07903777957f},
    {0.47023471429f, 1.08658953759f},
    {0.48874897619f, 1.09462239798f},
    {0.50720285714f, 1.10316330018f},
    {0.52558835714f, 1.11224144183f},
    {0.54389669048f, 1.12188861421f},
    {0.56211826190f, 1.13213939967f},
    {0.58024261905f, 1.14303145047f},
    {0.59825847619f, 1.15460566091f},
    {0.61615335714f, 1.16690711338f},
    {0.63391345238f, 1.17998560444f},
    {0.65152300000f, 1.19389708987f},
    {0.66896328571f, 1.20870580446f},
    {0.68621100000f, 1.22448751087f},
    {0.70323578571f, 1.24133415620f},
    {0.71999716667f, 1.25935962776f},
    {0.73643969048f, 1.27870875648f},
    {0.75250778571f, 1.29953256670f},
    {0.76817614286f, 1.32193822000f},
    {0.78342009524f, 1.34604270338f},
    {0.79828314286f, 1.37185833833f},
    {0.81267376190f, 1.39964322604f},
    {0.82656559524f, 1.42955958262f},
    {0.83983054762f, 1.46196539657f},
    {0.85234333333f, 1.49724142650f},
    {0.86394971429f, 1.53585530271f},
    {0.87422461905f, 1.57881139444f},
    {0.88382583095f, 1.62091537826f},
    {0.89571361286f, 1.67610209261f},
    {0.90490389167f, 1.72118819668f},
    {0.91526452143f, 1.77496904481f},
    {0.92651365452f, 1.83722833673f},
    {0.93437489976f, 1.88337590145f},
    {0.94654105500f, 1.95937892848f},
    {0.95476685095f, 2.01469745492f},
    {0.96720383310f, 2.10451495481f},
    {0.97546726405f, 2.16904926656f},
    {0.98774046786f, 2.27302748020f},
    {0.99579206762f, 2.34720582421f},
    {1.00763328857f, 2.46603526105f},
    {1.01533118405f, 2.55049232288f},
    {1.02287120929f, 2.63936582235f}
  };
  // clang-format on
  return new LookupRadialDistortion(
      kBlueDistortionLookup, sizeof(kBlueDistortionLookup) / sizeof(vec2));
}

LookupRadialDistortion* GetGreenDistortionLookup() {
  // clang-format off
  vec2 kGreenDistortionLookup[] = {
    {0.00000000000f, 1.00000000000f},
    {0.01898883333f, 1.00000000000f},
    {0.03797750000f, 1.00000000000f},
    {0.05696585714f, 1.00000000000f},
    {0.07595369048f, 1.00000000000f},
    {0.09494078571f, 1.00000000000f},
    {0.11392685714f, 1.00000000000f},
    {0.13291157143f, 1.00000000000f},
    {0.15189450000f, 1.00176560670f},
    {0.17087511905f, 1.00384553961f},
    {0.18985280952f, 1.00618614484f},
    {0.20882680952f, 1.00879302066f},
    {0.22779623810f, 1.01167234096f},
    {0.24675997619f, 1.01483135203f},
    {0.26571680952f, 1.01827767641f},
    {0.28466519048f, 1.02202026825f},
    {0.30360342857f, 1.02606859705f},
    {0.32252950000f, 1.03043334057f},
    {0.34144104762f, 1.03512630376f},
    {0.36033538095f, 1.04016038545f},
    {0.37920942857f, 1.04554970984f},
    {0.39805966667f, 1.05130981266f},
    {0.41688209524f, 1.05745768999f},
    {0.43567214286f, 1.06401204155f},
    {0.45442473810f, 1.07099310305f},
    {0.47313411905f, 1.07842314596f},
    {0.49179388095f, 1.08632639514f},
    {0.51039692857f, 1.09472920992f},
    {0.52893538095f, 1.10366038032f},
    {0.54740061905f, 1.11315113705f},
    {0.56578326190f, 1.12323535769f},
    {0.58407300000f, 1.13395008040f},
    {0.60225871429f, 1.14533547370f},
    {0.62032809524f, 1.15743581542f},
    {0.63826750000f, 1.17030000749f},
    {0.65606135714f, 1.18398295206f},
    {0.67369107143f, 1.19854780583f},
    {0.69113350000f, 1.21406895255f},
    {0.70835842857f, 1.23063670464f},
    {0.72532545238f, 1.24836302903f},
    {0.74197478571f, 1.26739777609f},
    {0.75822164286f, 1.28793886907f},
    {0.77407361905f, 1.31003521318f},
    {0.78948523810f, 1.33383710115f},
    {0.80448471429f, 1.35938255065f},
    {0.81901733333f, 1.38686361242f},
    {0.83305214286f, 1.41644808409f},
    {0.84646438095f, 1.44848277406f},
    {0.85912733333f, 1.48334485259f},
    {0.87088369048f, 1.52149970074f},
    {0.88131250000f, 1.56392750036f},
    {0.89105132929f, 1.60552684742f},
    {0.90312479476f, 1.66002695068f},
    {0.91244067452f, 1.70458805205f},
    {0.92297971714f, 1.75767475825f},
    {0.93440940905f, 1.81916050294f},
    {0.94237194976f, 1.86478635937f},
    {0.95471202405f, 1.93989738862f},
    {0.96305355738f, 1.99457325750f},
    {0.97567372071f, 2.08333293385f},
    {0.98407229071f, 2.14708073108f},
    {0.99653762071f, 2.24981649552f},
    {1.00471276167f, 2.32311751786f},
    {1.01672394000f, 2.44057411530f},
    {1.02452363381f, 2.52407947994f},
    {1.03216732667f, 2.61194301580f}
  };
  // clang-format on
  return new LookupRadialDistortion(
      kGreenDistortionLookup, sizeof(kGreenDistortionLookup) / sizeof(vec2));
}

LookupRadialDistortion* GetRedDistortionLookup() {
  // clang-format off
  vec2 kRedDistortionLookup[] = {
    {0.00000000000f, 1.00000000000f},
    {0.01906776190f, 1.00000000000f},
    {0.03813547619f, 1.00000000000f},
    {0.05720304762f, 1.00000000000f},
    {0.07627040476f, 1.00000000000f},
    {0.09533740476f, 1.00000000000f},
    {0.11440385714f, 1.00000000000f},
    {0.13346952381f, 1.00000000000f},
    {0.15253409524f, 1.00000000000f},
    {0.17159714286f, 1.00000000000f},
    {0.19065814286f, 1.00053530030f},
    {0.20971645238f, 1.00310924426f},
    {0.22877123810f, 1.00595236192f},
    {0.24782154762f, 1.00907150786f},
    {0.26686623810f, 1.01247435420f},
    {0.28590388095f, 1.01616968529f},
    {0.30493288095f, 1.02016688932f},
    {0.32395133333f, 1.02447646681f},
    {0.34295697619f, 1.02911011406f},
    {0.36194726190f, 1.03408046560f},
    {0.38091921429f, 1.03940151599f},
    {0.39986942857f, 1.04508858434f},
    {0.41879402381f, 1.05115843585f},
    {0.43768857143f, 1.05762946333f},
    {0.45654809524f, 1.06452169646f},
    {0.47536695238f, 1.07185711363f},
    {0.49413888095f, 1.07965956927f},
    {0.51285690476f, 1.08795508025f},
    {0.53151326190f, 1.09677206014f},
    {0.55009952381f, 1.10614118417f},
    {0.56860633333f, 1.11609607621f},
    {0.58702361905f, 1.12667304464f},
    {0.60534028571f, 1.13791190276f},
    {0.62354421429f, 1.14985618930f},
    {0.64162188095f, 1.16255413653f},
    {0.65955780952f, 1.17605992962f},
    {0.67733352381f, 1.19043584317f},
    {0.69492602381f, 1.20575517508f},
    {0.71230514286f, 1.22210708787f},
    {0.72943057143f, 1.23960199799f},
    {0.74623921429f, 1.25839340501f},
    {0.76262400000f, 1.27871385661f},
    {0.77861754762f, 1.30056919119f},
    {0.79415866667f, 1.32413401001f},
    {0.80926385714f, 1.34946540639f},
    {0.82390640476f, 1.37670655635f},
    {0.83805190476f, 1.40602920817f},
    {0.85157807143f, 1.43777181543f},
    {0.86435700000f, 1.47230885729f},
    {0.87622914286f, 1.51010361811f},
    {0.88677650000f, 1.55211817236f},
    {0.89663317738f, 1.59330127207f},
    {0.90883197952f, 1.64729627820f},
    {0.91827594357f, 1.69138814689f},
    {0.92892199405f, 1.74398939784f},
    {0.94047261548f, 1.80490554711f},
    {0.94852659262f, 1.85009630648f},
    {0.96099790167f, 1.92451421938f},
    {0.96945317500f, 1.97863645920f},
    {0.98221554286f, 2.06656418112f},
    {0.99069599476f, 2.12974390154f},
    {1.00331392976f, 2.23149730290f},
    {1.01157138762f, 2.30414058939f},
    {1.02372409452f, 2.42049694265f},
    {1.03162992905f, 2.50318810924f},
    {1.03934762000f, 2.59027212626f}
  };
  // clang-format on
  return new LookupRadialDistortion(
      kRedDistortionLookup, sizeof(kRedDistortionLookup) / sizeof(vec2));
}

HeadMountMetrics CreateHeadMountMetrics(const FieldOfView& l_fov,
                                        const FieldOfView& r_fov) {
  std::shared_ptr<ColorChannelDistortion> default_distortion_r(
      GetRedDistortionLookup());
  std::shared_ptr<ColorChannelDistortion> default_distortion_g(
      GetGreenDistortionLookup());
  std::shared_ptr<ColorChannelDistortion> default_distortion_b(
      GetBlueDistortionLookup());

  return HeadMountMetrics(
      kDefaultInterLensDistance, kDefaultTrayToLensDistance,
      kDefaultVirtualEyeToScreenDistance, kDefaultVerticalAlignment, l_fov,
      r_fov, default_distortion_r, default_distortion_g, default_distortion_b,
      HeadMountMetrics::EyeOrientation::kCCW0Degrees,
      HeadMountMetrics::EyeOrientation::kCCW0Degrees,
      kDefaultInterLensDistance / 2.0f);
}

HeadMountMetrics CreateHeadMountMetrics() {
  FieldOfView l_fov(kDefaultFovHalfAngleOutsideH, kDefaultFovHalfAngleInsideH,
                    kDefaultFovHalfAngleV, kDefaultFovHalfAngleV);
  FieldOfView r_fov(kDefaultFovHalfAngleInsideH, kDefaultFovHalfAngleOutsideH,
                    kDefaultFovHalfAngleV, kDefaultFovHalfAngleV);

  return CreateHeadMountMetrics(l_fov, r_fov);
}

DisplayMetrics CreateDisplayMetrics(vec2i screen_size) {
  vec2 meters_per_pixel(
      kScreenSizeInMeters[0] / static_cast<float>(screen_size[0]),
      kScreenSizeInMeters[1] / static_cast<float>(screen_size[1]));
  return DisplayMetrics(screen_size, meters_per_pixel, kScreenBorderSize,
                        1000.0f / kScreenRefreshRate, kDisplayOrientation);
}

HeadMountMetrics CreateUndistortedHeadMountMetrics() {
  FieldOfView l_fov(kDefaultFovHalfAngleOutsideH, kDefaultFovHalfAngleInsideH,
                    kDefaultFovHalfAngleV, kDefaultFovHalfAngleV);
  FieldOfView r_fov(kDefaultFovHalfAngleInsideH, kDefaultFovHalfAngleOutsideH,
                    kDefaultFovHalfAngleV, kDefaultFovHalfAngleV);
  return CreateUndistortedHeadMountMetrics(l_fov, r_fov);
}

HeadMountMetrics CreateUndistortedHeadMountMetrics(const FieldOfView& l_fov,
                                                   const FieldOfView& r_fov) {
  auto distortion_all = std::make_shared<IdentityDistortion>();

  return HeadMountMetrics(kDefaultInterLensDistance, kDefaultTrayToLensDistance,
                          kDefaultVirtualEyeToScreenDistance,
                          kDefaultVerticalAlignment, l_fov, r_fov,
                          distortion_all, distortion_all, distortion_all,
                          HeadMountMetrics::EyeOrientation::kCCW0Degrees,
                          HeadMountMetrics::EyeOrientation::kCCW0Degrees,
                          kDefaultInterLensDistance / 2.0f);
}

}  // namespace dvr
}  // namespace dvr
