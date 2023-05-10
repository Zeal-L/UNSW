//! This module contains the implementations of the "combine" quests.

use std::fmt::Display;
use crate::quest::{Quest, QuestEvent, QuestStatus};

/// A quest that requires the player must complete at least a certain number of the quests.
/// The player can choose which quests to complete.
#[derive(Clone)]
pub struct AtLeastNumQuests {
    /// The quests that the player must complete.
    pub quests: Vec<Box<dyn Quest<QuestEvent>>>,
    /// The number of quests that the player must complete.
    pub target_num: usize,
}

impl AtLeastNumQuests {
    /// Create a new quest that requires the player must complete at least a certain number of the quests.
    ///
    /// # Arguments
    /// * `quests` - The quests that the player must complete.
    /// * `target_num` - The number of quests that the player must complete.
    ///
    /// # Example
    /// ```
    /// use adventurers_quest::quest_combine::AtLeastNumQuests;
    /// use adventurers_quest::quest_single::BlocksWalkedQuest;
    /// use adventurers_quest::quest::{Quest, QuestEvent, BlockType, QuestStatus};
    /// use std::boxed::Box;
    ///
    /// let quest1 = Box::new(BlocksWalkedQuest::new(BlockType::Grass, 5, 1));
    /// let quest2 = Box::new(BlocksWalkedQuest::new(BlockType::Sand, 5, 1));
    /// let quests: Vec<Box<dyn Quest<QuestEvent>>> = vec![quest1, quest2];
    /// let quest = AtLeastNumQuests::new(quests, 1);
    /// assert_eq!(quest.quests.len(), 2);
    /// assert_eq!(quest.target_num, 1);
    /// assert_eq!(quest.is_complete(), QuestStatus::Ongoing);
    /// ```
    pub fn new(quests: Vec<Box<dyn Quest<QuestEvent>>>, target_num: usize) -> Self {
        Self { quests, target_num }
    }
}

impl Display for AtLeastNumQuests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = <dyn Quest<QuestEvent>>::get_complete_sign(self);

        write!(
            f,
            "[{}] You must complete at least {} of these quests:\n{}",
            status,
            self.target_num,
            self.quests
                .iter()
                .flat_map(|quest| quest
                    .to_string()
                    .lines()
                    .map(|line| format!("  {}", line))
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}

impl Quest<QuestEvent> for AtLeastNumQuests {
    /// Whenever something happens, you call "register_event" to tell the quest what's happened.
    /// The quest will update its status accordingly.
    ///
    /// # Arguments
    /// * `event` - The event that happened.
    ///
    /// # Example
    /// ```
    /// use adventurers_quest::quest::{Quest, QuestEvent, BlockType, QuestStatus};
    /// use adventurers_quest::quest_single::CollectQuest;
    /// use adventurers_quest::quest_combine::AtLeastNumQuests;
    ///
    /// let mut quest1 = CollectQuest::new(BlockType::Object('x'), 1);
    /// let mut quest2 = CollectQuest::new(BlockType::Object('y'), 1);
    /// let mut quest = AtLeastNumQuests::new(vec![Box::new(quest1), Box::new(quest2)], 1);
    ///
    /// assert_eq!(quest.is_complete(), QuestStatus::Ongoing);
    /// assert_eq!(format!("{}", quest), "[ ] You must complete at least 1 of these quests:
    ///   [ ] Collect a 'x'..
    ///   [ ] Collect a 'y'..");
    /// quest.register_event(QuestEvent::CollectItem(BlockType::Object('x')));
    /// assert_eq!(quest.is_complete(), QuestStatus::Complete);
    /// assert_eq!(format!("{}", quest), "[✅] You must complete at least 1 of these quests:
    ///   [✅] Collect a 'x'..
    ///   [ ] Collect a 'y'..");
    /// ```
    fn register_event(&mut self, event: QuestEvent) {
        for quest in self.quests.iter_mut() {
            if quest.is_complete() == QuestStatus::Complete {
                continue;
            }
            quest.register_event(event);
        }
    }

    fn reset(&mut self) {
        for quest in self.quests.iter_mut() {
            quest.reset();
        }
    }

    fn is_complete(&self) -> QuestStatus {
        (self
            .quests
            .iter()
            .filter(|quest| quest.is_complete() == QuestStatus::Complete)
            .count()
            >= self.target_num)
            .into()
    }
}

/// A quest that requires the player must first complete one quest, then another.
#[derive(Debug, Clone)]
pub struct ThenQuest<T: Quest<QuestEvent>, U: Quest<QuestEvent>>
where
    T: Clone,
    U: Clone,
{
    /// The first quest that the player must complete.
    first: T,
    /// The second quest that the player must complete.
    second: U,
}

impl<T: Quest<QuestEvent> + Clone, U: Quest<QuestEvent> + Clone> ThenQuest<T, U> {
    /// Create a new quest that requires the player must first complete one quest, then another.
    /// The first quest must be completed before the second quest can be started.
    ///
    /// # Arguments
    /// * `first` - The first quest that the player must complete.
    /// * `second` - The second quest that the player must complete.
    ///
    /// # Example
    /// ```
    /// use adventurers_quest::quest_combine::ThenQuest;
    /// use adventurers_quest::quest_single::BlocksWalkedQuest;
    /// use adventurers_quest::quest::{Quest, QuestEvent, BlockType, QuestStatus};
    ///
    /// let quest1 = BlocksWalkedQuest::new(BlockType::Grass, 1, 1);
    /// let quest2 = BlocksWalkedQuest::new(BlockType::Sand, 1, 1);
    /// let quest = ThenQuest::new(quest1, quest2);
    ///
    /// assert_eq!(quest.is_complete(), QuestStatus::Ongoing);
    /// assert_eq!(format!("{}", quest), "[ ] You must, in order, complete each of these quests:
    ///   [ ] Walk on a grass block..
    ///   [ ] Walk on a sand block..");
    /// ```
    pub fn new(first: T, second: U) -> Self {
        Self { first, second }
    }
}

impl<T: Quest<QuestEvent> + Clone, U: Quest<QuestEvent> + Clone> Display for ThenQuest<T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.is_complete() == QuestStatus::Complete {
            "✅"
        } else {
            " "
        };
        let first = self
            .first
            .to_string()
            .lines()
            .map(|line| format!("  {}", line))
            .collect::<Vec<String>>()
            .join("\n");

        let second = self
            .second
            .to_string()
            .lines()
            .map(|line| format!("  {}", line))
            .collect::<Vec<String>>()
            .join("\n");
        write!(
            f,
            "[{}] You must, in order, complete each of these quests:\n{}\n{}",
            status, first, second
        )
    }
}

impl<T: Quest<QuestEvent> + Clone, U: Quest<QuestEvent> + Clone> Quest<QuestEvent>
    for ThenQuest<T, U>
{
    /// Whenever something happens, you call "register_event" to tell the quest what's happened.
    /// The quest will update its status accordingly.
    ///
    /// # Arguments
    /// * `event` - The event that happened.
    ///
    /// # Example
    /// ```
    /// use adventurers_quest::quest::{Quest, QuestEvent, BlockType, QuestStatus};
    /// use adventurers_quest::quest_single::CollectQuest;
    /// use adventurers_quest::quest_combine::ThenQuest;
    ///
    /// let mut quest1 = CollectQuest::new(BlockType::Object('x'), 1);
    /// let mut quest2 = CollectQuest::new(BlockType::Object('y'), 1);
    /// let mut quest = ThenQuest::new(quest1, quest2);
    /// 
    /// quest.register_event(QuestEvent::CollectItem(BlockType::Object('y')));
    /// assert_eq!(quest.is_complete(), QuestStatus::Ongoing);
    /// assert_eq!(format!("{}", quest), "[ ] You must, in order, complete each of these quests:
    ///   [ ] Collect a 'x'..
    ///   [ ] Collect a 'y'..");
    /// quest.register_event(QuestEvent::CollectItem(BlockType::Object('x')));
    /// quest.register_event(QuestEvent::CollectItem(BlockType::Object('y')));
    /// assert_eq!(quest.is_complete(), QuestStatus::Complete);
    /// assert_eq!(format!("{}", quest), "[✅] You must, in order, complete each of these quests:
    ///   [✅] Collect a 'x'..
    ///   [✅] Collect a 'y'..");
    fn register_event(&mut self, event: QuestEvent) {
        if self.first.is_complete() == QuestStatus::Complete {
            self.second.register_event(event);
        } else {
            self.first.register_event(event);
        }
    }

    fn reset(&mut self) {
        self.first.reset();
        self.second.reset();
    }

    fn is_complete(&self) -> QuestStatus {
        if self.first.is_complete() == QuestStatus::Complete
            && self.second.is_complete() == QuestStatus::Complete
        {
            QuestStatus::Complete
        } else {
            QuestStatus::Ongoing
        }
    }
}
