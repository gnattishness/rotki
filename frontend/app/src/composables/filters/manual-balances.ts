import z from 'zod';
import { type MatchedKeyword, type SearchMatcher, assetDeserializer, assetSuggestions } from '@/types/filtering';
import type { FilterSchema } from '@/composables/filter-paginate';

enum ManualBalanceFilterKeys {
  LOCATION = 'location',
  LABEL = 'label',
  ASSET = 'asset',
}

enum ManualBalanceFilterValueKeys {
  LOCATION = 'location',
  LABEL = 'label',
  ASSET = 'asset',
}

export type Matcher = SearchMatcher<ManualBalanceFilterKeys, ManualBalanceFilterValueKeys>;

export type Filters = MatchedKeyword<ManualBalanceFilterValueKeys>;

export function useManualBalanceFilter(): FilterSchema<Filters, Matcher> {
  const filters = ref<Filters>({});

  const { t } = useI18n();
  const { assetSearch, assetInfo } = useAssetInfoRetrieval();
  const { associatedLocations } = storeToRefs(useHistoryStore());

  const matchers = computed<Matcher[]>(() => [
    {
      key: ManualBalanceFilterKeys.LOCATION,
      keyValue: ManualBalanceFilterValueKeys.LOCATION,
      description: t('common.location'),
      string: true,
      suggestions: () => get(associatedLocations),
      validate: location => get(associatedLocations).includes(location),
    },
    {
      key: ManualBalanceFilterKeys.LABEL,
      keyValue: ManualBalanceFilterValueKeys.LABEL,
      description: t('common.label'),
      string: true,
      suggestions: () => [],
      validate: (type: string) => !!type,
    },
    {
      key: ManualBalanceFilterKeys.ASSET,
      keyValue: ManualBalanceFilterValueKeys.ASSET,
      description: t('common.asset'),
      asset: true,
      suggestions: assetSuggestions(assetSearch),
      deserializer: assetDeserializer(assetInfo),
    },
  ]);

  const RouteFilterSchema = z.object({
    [ManualBalanceFilterValueKeys.LOCATION]: z.string().optional(),
    [ManualBalanceFilterValueKeys.LABEL]: z.string().optional(),
    [ManualBalanceFilterValueKeys.ASSET]: z.string().optional(),
  });

  return {
    matchers,
    filters,
    RouteFilterSchema,
  };
}
