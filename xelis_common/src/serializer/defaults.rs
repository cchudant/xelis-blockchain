use crate::crypto::hash::Hash;
use super::{Serializer, Writer, Reader, ReaderError};
use std::{collections::{HashSet, BTreeSet, HashMap}, borrow::Cow, hash::Hash as StdHash};
use indexmap::IndexSet;
use log::{error, warn};

// Used for Tips storage
impl Serializer for HashSet<Hash> {
    fn write(&self, writer: &mut Writer) {
        for hash in self {
            writer.write_hash(hash);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let total_size = reader.total_size();
        if total_size % 32 != 0 {
            error!("Invalid size: {}, expected a multiple of 32 for hashes", total_size);
            return Err(ReaderError::InvalidSize)
        }

        let count = total_size / 32;
        let mut tips = HashSet::with_capacity(count);
        for _ in 0..count {
            let hash = reader.read_hash()?;
            tips.insert(hash);
        }

        if tips.len() != count {
            error!("Invalid size: received {} elements while sending {}", tips.len(), count);
            return Err(ReaderError::InvalidSize) 
        }

        Ok(tips)
    }
}

// Implement Serializer for all unsigned numbers

impl Serializer for u128 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u128(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u128()?)
    }
}

impl Serializer for u64 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u64()?)
    }
}

impl Serializer for u32 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u32(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u32()?)
    }
}

impl Serializer for u16 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u16(*self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u16()?)
    }
}

// Implement Serializer for u8
impl Serializer for u8 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(*self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u8()?)
    }
}

const MAX_ITEMS: usize = 1024;

impl<T: Serializer + std::hash::Hash + Ord> Serializer for BTreeSet<T> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let count = reader.read_u16()?;
        if count > MAX_ITEMS as u16 {
            warn!("Received {} while maximum is set to {}", count, MAX_ITEMS);
            return Err(ReaderError::InvalidSize)
        }

        let mut set = BTreeSet::new();
        for _ in 0..count {
            let value = T::read(reader)?;
            if !set.insert(value) {
                error!("Value is duplicated in BTreeSet");
                return Err(ReaderError::InvalidSize)
            }
        }
        Ok(set)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.len() as u16);
        for el in self {
            el.write(writer);
        }
    }
}

impl<T: Serializer + std::hash::Hash + Eq> Serializer for IndexSet<T> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let count = reader.read_u16()?;
        if count > MAX_ITEMS as u16 {
            warn!("Received {} while maximum is set to {}", count, MAX_ITEMS);
            return Err(ReaderError::InvalidSize)
        }

        let mut set = IndexSet::new();
        for _ in 0..count {
            let value = T::read(reader)?;
            if !set.insert(value) {
                error!("Value is duplicated in IndexSet");
                return Err(ReaderError::InvalidSize)
            }
        }
        Ok(set)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.len() as u16);
        for el in self {
            el.write(writer);
        }
    }
}

impl<T: Serializer + Clone> Serializer for Cow<'_, T> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Cow::Owned(T::read(reader)?))
    }

    fn write(&self, writer: &mut Writer) {
        self.as_ref().write(writer);
    }
}

impl<T: Serializer> Serializer for Option<T> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        if reader.read_bool()? {
            Ok(Some(T::read(reader)?))
        } else {
            Ok(None)
        }
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_bool(self.is_some());
        if let Some(value) = self {
            value.write(writer);
        }
    }
}

impl<T: Serializer> Serializer for Vec<T> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let count = reader.read_u16()?;
        if count > MAX_ITEMS as u16 {
            warn!("Received {} while maximum is set to {}", count, MAX_ITEMS);
            return Err(ReaderError::InvalidSize)
        }

        let mut values = Vec::with_capacity(count as usize);
        for _ in 0..count {
            values.push(T::read(reader)?);
        }

        Ok(values)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.len() as u16);
        for el in self {
            el.write(writer);
        }
    }
}

impl Serializer for String {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        reader.read_string()
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_string(self);
    }
}

impl Serializer for bool {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        reader.read_bool()
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_bool(*self);
    }
}


// Supports up to 2^16 elements
impl<K: Serializer + Eq + StdHash, V: Serializer + Eq + StdHash> Serializer for HashMap<K, V> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let size = reader.read_u16()?;
        let mut map = HashMap::with_capacity(size as usize);
        for _ in 0..size {
            let k = K::read(reader)?;
            let v = V::read(reader)?;
            map.insert(k, v);
        }

        Ok(map)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.len() as u16);
        for (key, value) in self.iter() {
            key.write(writer);
            value.write(writer);
        }
    }
}

impl<const N: usize> Serializer for [u8; N] {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let bytes = reader.read_bytes(N)?;
        Ok(
            bytes
        )
    }
}